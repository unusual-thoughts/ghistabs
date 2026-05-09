package ghistabs.importer

import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.LocalVariableImpl
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.SourceType
import ghistabs.builder.Attribution
import ghistabs.builder.TypeAst
import ghistabs.builder.TypeRegistry
import ghistabs.container.StabReader
import ghistabs.container.StabRecord
import ghistabs.container.StabType
import ghistabs.parser.Parser
import ghistabs.parser.StabsParseException
import ghistabs.parser.SymbolDecl

class StabsImporter(
    private val ctx: ImportContext,
) {
    fun run(): PassResult {
        val readerResult =
            StabReader.fromProgram(ctx.program) ?: run {
                ctx.sink.log("no-stabs", "No .stab/.stabstr block found; skipping import.")
                return PassResult()
            }

        val records = readerResult.records
        ctx.monitor.initialize(records.size.toLong())
        ctx.monitor.message = "Stabs: parsing"

        // Pass A — parse + harvest
        val typeAsts = mutableListOf<TypeAst>()
        val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
        val openFunctions = mutableListOf<OpenFunction>()
        val parseErrors = passAHarvest(records, typeAsts, symbolsByCu, openFunctions)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(ctx.dtm, ctx.sink)
        val txB = ctx.program.startTransaction("Stabs: materialise types")
        try {
            typeRegistry.materialiseAll(typeAsts) { name, cus ->
                Attribution.categoryFor(name, cus)
            }
        } finally {
            ctx.program.endTransaction(txB, true)
        }

        // Pass C — apply symbols
        val txC = ctx.program.startTransaction("Stabs: apply symbols")
        val applyResult =
            try {
                applyAllSymbols(symbolsByCu, openFunctions, typeRegistry)
            } finally {
                ctx.program.endTransaction(txC, true)
            }

        return PassResult(
            recordsRead = readerResult.recordCount,
            recordsParsed = records.size - parseErrors,
            parseErrors = parseErrors,
            typesMaterialised = typeAsts.size,
            functionsApplied = applyResult.functions,
            globalsApplied = applyResult.globals,
        )
    }

    internal fun runWithRecords(records: List<StabRecord>): PassResult {
        ctx.monitor.initialize(records.size.toLong())
        ctx.monitor.message = "Stabs: parsing"

        // Pass A — parse + harvest
        val typeAsts = mutableListOf<TypeAst>()
        val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
        val openFunctions = mutableListOf<OpenFunction>()
        val parseErrors = passAHarvest(records, typeAsts, symbolsByCu, openFunctions)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(ctx.dtm, ctx.sink)
        val txB = ctx.program.startTransaction("Stabs: materialise types")
        try {
            typeRegistry.materialiseAll(typeAsts) { name, cus ->
                Attribution.categoryFor(name, cus)
            }
        } finally {
            ctx.program.endTransaction(txB, true)
        }

        // Pass C — apply symbols
        val txC = ctx.program.startTransaction("Stabs: apply symbols")
        val applyResult =
            try {
                applyAllSymbols(symbolsByCu, openFunctions, typeRegistry)
            } finally {
                ctx.program.endTransaction(txC, true)
            }

        return PassResult(
            recordsRead = records.size,
            recordsParsed = records.size - parseErrors,
            parseErrors = parseErrors,
            typesMaterialised = typeAsts.size,
            functionsApplied = applyResult.functions,
            globalsApplied = applyResult.globals,
        )
    }

    internal fun passAHarvest(
        records: List<StabRecord>,
        typeAsts: MutableList<TypeAst>,
        symbolsByCu: MutableMap<String, MutableList<HarvestedSymbol>>,
        openFunctions: MutableList<OpenFunction>,
    ): Int {
        var parseErrors = 0
        var currentCu: String = "<unknown>"
        var currentFunction: OpenFunction? = null

        for ((i, rec) in records.withIndex()) {
            ctx.monitor.checkCancelled()
            ctx.monitor.incrementProgress(1)

            when (rec.type) {
                StabType.N_SO, StabType.N_SOL -> {
                    if (rec.name.isNotEmpty()) currentCu = rec.name
                }

                StabType.N_FUN -> {
                    val addrSpace = ctx.program.addressFactory.defaultAddressSpace
                    if (rec.name.isEmpty()) {
                        // End-of-function marker: rec.value = function size relative to start.
                        currentFunction?.let { it.sizeBytes = rec.value }
                        currentFunction = null
                    } else {
                        val addr = addrSpace.getAddress(rec.value)
                        // Pull mangled name from before the colon.
                        val mangled = rec.name.substringBefore(':')
                        ctx.resolver.recordFromStab(mangled, addr)
                        try {
                            val decl = Parser(rec.name).parseSymbol() as? SymbolDecl.Function
                            if (decl != null) {
                                val open =
                                    OpenFunction(
                                        name = mangled,
                                        addr = addr,
                                        decl = decl,
                                        cu = currentCu,
                                        locals = mutableListOf(),
                                        params = mutableListOf(),
                                        scopeBrackets = mutableListOf(),
                                    )
                                openFunctions += open
                                currentFunction = open
                            }
                        } catch (e: StabsParseException) {
                            parseErrors++
                            ctx.sink.log("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
                        }
                    }
                }

                StabType.N_GSYM -> {
                    harvestSymbol(rec, currentCu, symbolsByCu) { parseErrors++ }
                }

                StabType.N_STSYM, StabType.N_LCSYM -> {
                    val addrSpace = ctx.program.addressFactory.defaultAddressSpace
                    val addr = addrSpace.getAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    ctx.resolver.recordFromStab(mangled, addr)
                    harvestSymbol(rec, currentCu, symbolsByCu) { parseErrors++ }
                }

                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = currentFunction ?: continue
                    try {
                        val decl = Parser(rec.name).parseSymbol()
                        when (decl) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> open.params += ParamRecord(decl, rec.value)
                            else -> Unit
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        ctx.sink.log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> {
                    val open = currentFunction
                    try {
                        val decl = Parser(rec.name).parseSymbol()
                        when (decl) {
                            is SymbolDecl.TaggedType -> {
                                typeAsts += TypeAst(decl.id, decl.name, decl.body, currentCu)
                            }

                            is SymbolDecl.Typedef -> {
                                typeAsts += TypeAst(decl.id, decl.name, decl.body, currentCu)
                            }

                            is SymbolDecl.StackLocal, is SymbolDecl.RegLocal, is SymbolDecl.StaticVar -> {
                                open?.locals?.add(
                                    LocalRecord(decl, rec.value),
                                )
                            }

                            else -> {
                                Unit
                            }
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        ctx.sink.log("parse-error", "lsym @$i: ${e.message}")
                    }
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> {
                    currentFunction?.scopeBrackets?.add(rec.type to rec.value)
                }

                else -> {
                    Unit
                } // ignore N_SLINE, N_OPT, etc.
            }
        }
        return parseErrors
    }

    private fun harvestSymbol(
        rec: StabRecord,
        currentCu: String,
        symbolsByCu: MutableMap<String, MutableList<HarvestedSymbol>>,
        onError: () -> Unit,
    ) {
        try {
            val decl = Parser(rec.name).parseSymbol()
            symbolsByCu.getOrPut(currentCu) { mutableListOf() } += HarvestedSymbol(decl, rec.type, rec.value)
        } catch (e: StabsParseException) {
            onError()
            ctx.sink.log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }

    internal fun applyAllSymbols(
        symbolsByCu: Map<String, List<HarvestedSymbol>>,
        openFunctions: List<OpenFunction>,
        typeRegistry: TypeRegistry,
    ): ApplyResult {
        val source = SourceType.IMPORTED
        val funcMgr = ctx.program.functionManager
        val listing = ctx.program.listing
        var functions = 0
        var globals = 0

        for (open in openFunctions) {
            try {
                val existing = funcMgr.getFunctionAt(open.addr)
                val func =
                    existing
                        ?: funcMgr.createFunction(open.name, open.addr, /* body */ null, source)
                        ?: continue

                // Apply return type from the parsed signature.
                val retDt = typeRegistry.dataTypeFor(open.decl.signature)
                if (retDt != null) func.setReturnType(retDt, source)

                // Build parameters from the recorded N_PSYM / N_RSYM records.
                val params =
                    open.params.mapIndexed { i, p ->
                        val pdecl = p.decl
                        val (pname, pdt) =
                            when (pdecl) {
                                is SymbolDecl.StackParam -> pdecl.name to typeRegistry.dataTypeFor(pdecl.type)
                                is SymbolDecl.RegParam -> pdecl.name to typeRegistry.dataTypeFor(pdecl.type)
                                else -> "arg$i" to null
                            }
                        ParameterImpl(
                            pname,
                            pdt ?: Undefined4DataType.dataType,
                            ctx.program,
                            source,
                        )
                    }
                if (params.isNotEmpty()) {
                    func.replaceParameters(
                        params,
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                        true,
                        source,
                    )
                }

                // Apply locals.
                for (loc in open.locals) {
                    applyLocal(func, loc, typeRegistry, source)
                }

                // Apply scope plate comments.
                if (ctx.options.applyPlateComments) applyScopeComments(func, open)

                functions++
            } catch (t: Throwable) {
                ctx.sink.log("apply-error", "function ${open.name} @ ${open.addr}: ${t.message}")
            }
        }

        // Globals + file-statics.
        for ((cu, syms) in symbolsByCu) {
            for (h in syms) {
                try {
                    when (val d = h.decl) {
                        is SymbolDecl.Global -> applyGlobal(d, typeRegistry, source).let { if (it) globals++ }
                        is SymbolDecl.StaticVar -> applyStatic(d, h.rawValue, typeRegistry, source).let { if (it) globals++ }
                        else -> Unit
                    }
                } catch (t: Throwable) {
                    ctx.sink.log("apply-error", "symbol ${h.decl.name} in $cu: ${t.message}")
                }
            }
        }

        return ApplyResult(functions, globals)
    }

    private fun applyLocal(
        func: Function,
        loc: LocalRecord,
        typeRegistry: TypeRegistry,
        source: SourceType,
    ) {
        val decl = loc.decl
        val dt =
            when (decl) {
                is SymbolDecl.StackLocal -> typeRegistry.dataTypeFor(decl.type) ?: Undefined4DataType.dataType
                is SymbolDecl.RegLocal -> typeRegistry.dataTypeFor(decl.type) ?: Undefined4DataType.dataType
                is SymbolDecl.StaticVar -> typeRegistry.dataTypeFor(decl.type) ?: Undefined4DataType.dataType
                else -> return
            }
        try {
            when (decl) {
                is SymbolDecl.StackLocal -> {
                    val stackOffset = loc.rawValue.toInt()
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                }

                is SymbolDecl.RegLocal -> {
                    // For now, treat register locals as stack locals at offset 0
                    // The register mapping question is deferred (see plan)
                    val lv = LocalVariableImpl(decl.name, dt, 0, ctx.program, source)
                    func.addLocalVariable(lv, source)
                }

                is SymbolDecl.StaticVar -> {
                    // Static locals stay as locals, not globals
                    val lv = LocalVariableImpl(decl.name, dt, 0, ctx.program, source)
                    func.addLocalVariable(lv, source)
                }
            }
        } catch (e: Exception) {
            ctx.sink.log("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}")
        }
    }

    private fun applyScopeComments(
        func: Function,
        open: OpenFunction,
    ) {
        // Pair LBRAC (open) with matching RBRAC (close). For each pair, list
        // the locals whose record appears inside the bracket range and
        // attach a plate comment at the LBRAC address.
        val pairs = computePairs(open.scopeBrackets, open.locals)
        for ((openOff, closeOff, localsInScope) in pairs) {
            try {
                val addr = func.entryPoint.add(openOff)
                val text = "Stabs scope locals: " + localsInScope.joinToString(", ") { it.decl.name }
                // 3 is CodeUnit.PLATE_COMMENT constant value
                ctx.program.listing.setComment(addr, 3, text)
            } catch (e: Exception) {
                ctx.sink.log("scope-comment-error", "Failed to set scope comment: ${e.message}")
            }
        }
    }

    private fun computePairs(
        scopeBrackets: List<Pair<StabType, Long>>,
        locals: List<LocalRecord>,
    ): List<Triple<Long, Long, List<LocalRecord>>> {
        val pairs = mutableListOf<Triple<Long, Long, List<LocalRecord>>>()
        val stack = mutableListOf<Pair<Int, Long>>() // (scopeBracket index, offset)

        for ((i, bracket) in scopeBrackets.withIndex()) {
            when (bracket.first) {
                StabType.N_LBRAC -> {
                    stack.add(i to bracket.second)
                }

                StabType.N_RBRAC -> {
                    if (stack.isNotEmpty()) {
                        val (openIdx, openOff) = stack.removeAt(stack.size - 1)
                        val closeOff = bracket.second
                        // Find locals that fall within this bracket range
                        // For v1, we just collect all locals (a simplification)
                        pairs.add(Triple(openOff, closeOff, locals.toList()))
                    }
                }

                else -> {
                    Unit
                }
            }
        }
        return pairs
    }

    private fun applyGlobal(
        decl: SymbolDecl.Global,
        typeRegistry: TypeRegistry,
        source: SourceType,
    ): Boolean {
        val addr =
            ctx.resolver.resolve(decl.name) ?: run {
                ctx.sink.log("unresolved-symbol", "global ${decl.name}")
                return false
            }
        val dt = typeRegistry.dataTypeFor(decl.type) ?: return false
        try {
            ctx.program.listing.createData(addr, dt)
        } catch (e: Exception) {
            ctx.sink.log("apply-error", "Failed to create global data at $addr: ${e.message}")
            return false
        }
        return true
    }

    private fun applyStatic(
        decl: SymbolDecl.StaticVar,
        rawAddr: Long,
        typeRegistry: TypeRegistry,
        source: SourceType,
    ): Boolean {
        val addr =
            ctx.program.addressFactory.defaultAddressSpace
                .getAddress(rawAddr)
        val dt = typeRegistry.dataTypeFor(decl.type) ?: return false
        try {
            ctx.program.listing.createData(addr, dt)
        } catch (e: Exception) {
            ctx.sink.log("apply-error", "Failed to create static data at $addr: ${e.message}")
            return false
        }
        return true
    }

    internal data class HarvestedSymbol(
        val decl: SymbolDecl,
        val recordType: StabType,
        val rawValue: Long,
    )

    internal data class OpenFunction(
        val name: String,
        val addr: ghidra.program.model.address.Address,
        val decl: SymbolDecl.Function,
        val cu: String,
        val locals: MutableList<LocalRecord>,
        val params: MutableList<ParamRecord>,
        val scopeBrackets: MutableList<Pair<StabType, Long>>,
        var sizeBytes: Long = 0L,
    )

    internal data class ParamRecord(
        val decl: SymbolDecl,
        val rawValue: Long,
    )

    internal data class LocalRecord(
        val decl: SymbolDecl,
        val rawValue: Long,
    )

    internal data class ApplyResult(
        val functions: Int,
        val globals: Int,
    )
}
