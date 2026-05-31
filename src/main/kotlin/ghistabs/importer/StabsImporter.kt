package ghistabs.importer

import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.CommentType
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
import ghistabs.parser.IncludeContext
import ghistabs.parser.LogSink
import ghistabs.parser.Parser
import ghistabs.parser.StabsParseException
import ghistabs.parser.SymbolDecl
import ghistabs.parser.TypeDecl
import ghistabs.replace.DemanglerReplacer

class StabsImporter(
    internal val ctx: ImportContext,
) : LogSink {
    override fun log(
        tag: String,
        message: String,
    ) {
        ctx.sink.log(tag, message)
    }

    fun run(): PassResult {
        val readerResult = StabReader.fromProgram(ctx.program)
        if (readerResult == null) {
            ctx.sink.log("no-stabs", "No .stab/.stabstr block found; skipping import.")
            ctx.diagnostics.writeSummary(ctx.sink)
            return PassResult()
        }

        val records = readerResult.records
        val result = runOnRecords(records, readerResult.recordCount)
        return result.copy(recordsRead = readerResult.recordCount)
    }

    internal fun runWithRecords(records: List<StabRecord>): PassResult = runOnRecords(records, records.size)

    private fun runOnRecords(
        records: List<StabRecord>,
        recordCount: Int,
    ): PassResult {
        ctx.monitor.initialize(records.size.toLong())
        ctx.monitor.message = "Stabs: parsing"

        // Pass A — parse + harvest
        val typeAsts = mutableListOf<TypeAst>()
        val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
        val openFunctions = mutableListOf<OpenFunction>()
        val includesByFile = mutableMapOf<String, IncludeContext>()
        val parseErrors = passAHarvest(records, typeAsts, symbolsByCu, openFunctions, includesByFile)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(ctx.dtm, ctx.sink, ctx.diagnostics)
        typeRegistry.setIncludeContexts(includesByFile)
        val txB = ctx.program.startTransaction("Stabs: materialise types")
        try {
            typeRegistry.materialiseAll(typeAsts.associateBy { it.id }) { name, cus ->
                Attribution.categoryFor(name, cus, ctx.diagnostics)
            }
        } finally {
            ctx.program.endTransaction(txB, true)
        }

        // Pass C — apply symbols
        val txC = ctx.program.startTransaction("Stabs: apply symbols")
        val applyResult =
            try {
                applyAllSymbols(typeAsts, symbolsByCu, openFunctions, typeRegistry)
            } finally {
                ctx.program.endTransaction(txC, true)
            }

        // Emit end-of-run diagnostics summary
        ctx.diagnostics.writeSummary(ctx.sink)

        return PassResult(
            recordsRead = recordCount,
            recordsParsed = records.size - parseErrors,
            parseErrors = parseErrors,
            typesMaterialised = typeAsts.size,
            functionsApplied = applyResult.functions,
            globalsApplied = applyResult.globals,
            classesApplied = applyResult.classes,
        )
    }

    internal fun passAHarvest(
        records: List<StabRecord>,
        typeAsts: MutableList<TypeAst>,
        symbolsByCu: MutableMap<String, MutableList<HarvestedSymbol>>,
        openFunctions: MutableList<OpenFunction>,
        includesByFile: MutableMap<String, IncludeContext> = mutableMapOf(),
    ): Int {
        var parseErrors = 0
        var currentCu = "<unknown>"
        var currentFunction: OpenFunction? = null
        var currentInclude: IncludeContext? = null
        // Allocate ONE shared HeaderRegistry for all per-CU IncludeContext instances.
        // This ensures cross-CU dedup: two CUs with the same (filename, checksum) BINCL
        // get the SAME HeaderFile instance via the shared registry.
        val sharedHeaderRegistry = ghistabs.parser.HeaderRegistry()

        for ((i, rec) in records.withIndex()) {
            ctx.monitor.checkCancelled()
            ctx.monitor.incrementProgress(1)

            when (rec.type) {
                StabType.N_SO -> {
                    if (rec.name.isNotEmpty()) {
                        currentCu = rec.name
                        currentInclude = IncludeContext(rec.name, this, sharedHeaderRegistry)
                        currentInclude.openSource(rec.name)
                        includesByFile[rec.name] = currentInclude
                    }
                }

                StabType.N_SOL -> {
                    if (rec.name.isNotEmpty()) {
                        currentCu = rec.name
                        currentInclude?.switchSource(rec.name)
                    }
                }

                StabType.N_BINCL -> {
                    val filename = rec.name.ifEmpty { "<unknown>" }
                    val checksum = rec.value
                    currentInclude?.beginInclude(filename, checksum)
                }

                StabType.N_EINCL -> {
                    currentInclude?.endInclude()
                }

                StabType.N_EXCL -> {
                    val filename = rec.name.ifEmpty { "<unknown>" }
                    val checksum = rec.value
                    currentInclude?.reMountExcluded(filename, checksum)
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
                        when (val decl = Parser(rec.name).parseSymbol()) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> {
                                open.params +=
                                    ParamRecord(
                                        decl,
                                        rec.value,
                                    )
                            }

                            else -> {}
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        ctx.sink.log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> {
                    val open = currentFunction
                    try {
                        when (val decl = Parser(rec.name).parseSymbol()) {
                            is SymbolDecl.TaggedType -> {
                                val canonicalId = currentInclude?.canonicalTypeId(decl.id) ?: decl.id
                                val canonicalBody = currentInclude?.canonicalizeTypeDecl(decl.body) ?: decl.body
                                typeAsts += TypeAst(canonicalId, decl.name, canonicalBody, currentCu)
                            }

                            is SymbolDecl.Typedef -> {
                                val canonicalId = currentInclude?.canonicalTypeId(decl.id) ?: decl.id
                                val canonicalBody = currentInclude?.canonicalizeTypeDecl(decl.body) ?: decl.body
                                typeAsts += TypeAst(canonicalId, decl.name, canonicalBody, currentCu)
                            }

                            is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                                open?.locals?.add(LocalRecord(decl, rec.value, i))
                            }

                            is SymbolDecl.StaticVar -> {
                                // Function-scope static variables get their actual address from rec.value
                                symbolsByCu.getOrPut(currentCu) { mutableListOf() } +=
                                    HarvestedSymbol(
                                        decl,
                                        rec.type,
                                        rec.value,
                                    )
                            }

                            else -> {}
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        ctx.sink.log("parse-error", "lsym @$i: ${e.message}")
                    }
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> {
                    currentFunction?.scopeBrackets?.add(Triple(rec.type, rec.value, i))
                }

                else -> {}
                // ignore N_SLINE, N_OPT, etc.
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
        typeAsts: List<TypeAst>,
        symbolsByCu: Map<String, List<HarvestedSymbol>>,
        openFunctions: List<OpenFunction>,
        typeRegistry: TypeRegistry,
    ): ApplyResult {
        val source = SourceType.IMPORTED
        val funcMgr = ctx.program.functionManager
        var functions = 0
        var globals = 0
        var classes = 0

        // Run demangler stub replacement before applying symbols
        DemanglerReplacer(ctx, typeRegistry).run()

        for (open in openFunctions) {
            try {
                val existing = funcMgr.getFunctionAt(open.addr)
                val func =
                    existing
                        ?: funcMgr.createFunction(open.name, open.addr, null, source)
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
                // Always apply parameters (even if empty) to explicitly set function signature
                func.replaceParameters(
                    params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    true,
                    source,
                )

                // Apply locals.
                for (loc in open.locals) {
                    applyLocal(func, loc, typeRegistry, source)
                }

                // Apply scope plate comments.
                if (ctx.options.applyPlateComments) applyScopeComments(func, open)

                functions++
            } catch (t: Throwable) {
                ctx.sink.bookmark("apply-error", open.addr, "function ${open.name}: ${t.message}")
            }
        }

        // Globals + file-statics.
        val allHarvestedSymbols = symbolsByCu.values.flatten()
        for ((cu, syms) in symbolsByCu) {
            for (h in syms) {
                try {
                    when (val d = h.decl) {
                        is SymbolDecl.Global -> applyGlobal(d, typeRegistry).let { if (it) globals++ }
                        is SymbolDecl.StaticVar -> applyStatic(d, h.rawValue, typeRegistry).let { if (it) globals++ }
                        else -> Unit
                    }
                } catch (t: Throwable) {
                    ctx.sink.log("apply-error", "symbol ${h.decl.name} in $cu: ${t.message}")
                }
            }
        }

        // .bss coverage analysis: detect uncovered ranges in the .bss section.
        analyzeBssCoverage(allHarvestedSymbols)

        // Classes + vtables.
        if (ctx.options.applyVtables) {
            val structAstsByName =
                typeAsts
                    .mapNotNull { ast ->
                        val body = ast.body as? TypeDecl.Struct ?: return@mapNotNull null
                        ast.name to body
                    }.toMap()
            val typeAstsById = typeAsts.associateBy { it.id }
            val classBuilder =
                ghistabs.builder.ClassBuilder(
                    ctx.program,
                    typeRegistry,
                    ctx.resolver,
                    ctx.sink,
                    structAstsByName,
                    typeAstsById,
                    ctx,
                )
            for (ast in typeAsts) {
                val body = ast.body as? TypeDecl.Struct ?: continue
                if (body.methods.isEmpty() && !body.hasVTablePointerMarker) continue
                try {
                    val category = Attribution.categoryFor(ast.name, setOf(ast.cuFile), ctx.diagnostics)
                    classBuilder.build(ast.name, body, category)
                    classes++
                } catch (t: Throwable) {
                    ctx.sink.log("class-apply-error", "${ast.name}: ${t.message}")
                }
            }
        }

        return ApplyResult(functions, globals, classes)
    }

    private fun analyzeBssCoverage(allHarvested: List<HarvestedSymbol>) {
        val bssBlock = ctx.program.memory.getBlock(".bss") ?: return
        val addrSpace = ctx.program.addressFactory.defaultAddressSpace

        // Build list of harvested symbols with resolved addresses
        val harvestedAddrs =
            allHarvested.mapNotNull {
                val name = (it.decl as? SymbolDecl.Global)?.name ?: return@mapNotNull null
                val addr = ctx.resolver.resolve(name)?.offset
                HarvestedAddr(name, addr)
            }

        // Scan .bss block at 4-byte intervals, checking for uncovered regions
        var addr = bssBlock.start
        while (addr <= bssBlock.end) {
            ctx.monitor.checkCancelled()

            // Skip addresses that already have a symbol or defined data
            if (ctx.program.symbolTable.getPrimarySymbol(addr) == null &&
                ctx.program.listing.getDefinedDataAt(addr) == null
            ) {
                val rangeEnd = addr.add(3)
                val pureRange = AddrRange(addr.offset, rangeEnd.offset)
                val result = BssCoverageDecision.classify(pureRange, harvestedAddrs)

                when (result) {
                    is CoverageResult.NoCoverage -> {
                        ctx.sink.log("stabs-no-coverage", "@ $addr..$rangeEnd: no stabs records cover this range")
                    }

                    is CoverageResult.Covered -> {
                        result.coverers.forEach {
                            ctx.sink.log("stabs-coverage", "@ $addr..$rangeEnd: covered by ${it.symbolName}")
                        }
                    }
                }
            }

            addr = addr.add(4)
        }
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
                else -> return
            }
        try {
            when (decl) {
                is SymbolDecl.StackLocal -> {
                    val stackOffset = loc.rawValue.toInt()
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    ctx.diagnostics.inc("local-var-add-success")
                }

                is SymbolDecl.RegLocal -> {
                    ctx.sink.log(
                        "regparam-deferred",
                        "Register local '${decl.name}' in function deferred (register mapping not implemented)",
                    )
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
        val pairs = ScopePairs.compute(open.scopeBrackets, open.locals)
        for ((openOff, _, localsInScope) in pairs) {
            try {
                val addr = func.entryPoint.add(openOff)
                if (!ScopePlateDecision.shouldEmitScopePlate(localsInScope.size)) {
                    ctx.diagnostics.recordEmptyScope(addr.toString(), func.name)
                    continue
                }
                val text = "Stabs scope locals: " + localsInScope.joinToString(", ") { it.decl.name }
                ctx.program.listing.setComment(addr, CommentType.PLATE, text)
            } catch (e: Exception) {
                ctx.sink.log("scope-comment-error", "Failed to set scope comment: ${e.message}")
            }
        }
    }

    private fun applyGlobal(
        decl: SymbolDecl.Global,
        typeRegistry: TypeRegistry,
    ): Boolean {
        val addr =
            ctx.resolver.resolve(decl.name) ?: run {
                ctx.sink.log("unresolved-symbol", "global ${decl.name}")
                ctx.diagnostics.recordGlobal(decl.name, "skipped", dtKind = "unknown", reason = "unresolved-symbol")
                return false
            }
        val dt =
            typeRegistry.dataTypeFor(decl.type) ?: run {
                ctx.diagnostics.recordGlobal(addr.toString(), "skipped", dtKind = "unknown", reason = "no-resolved-type")
                return false
            }
        val dtKind = classifyDataType(dt)
        try {
            // Clear any existing code units before creating data to avoid conflicts
            ctx.program.listing.clearCodeUnits(addr, addr.add((dt.length - 1).toLong()), false)
            ctx.program.listing.createData(addr, dt)
            ctx.diagnostics.recordGlobal(addr.toString(), "applied", dtKind = dtKind)
        } catch (e: Exception) {
            ctx.sink.log("apply-error", "Failed to create global data at $addr: ${e.message}")
            ctx.diagnostics.recordGlobal(addr.toString(), "skipped", dtKind = dtKind, reason = "create-data-failed")
            return false
        }
        return true
    }

    private fun classifyDataType(dt: ghidra.program.model.data.DataType): String =
        when (dt) {
            is ghidra.program.model.data.Structure -> "Structure"
            is ghidra.program.model.data.Union -> "Union"
            is ghidra.program.model.data.Array -> "Array"
            is ghidra.program.model.data.Pointer -> "Pointer"
            is ghidra.program.model.data.FunctionDefinition -> "FunctionDefinition"
            is ghidra.program.model.data.Enum -> "Enum"
            else -> dt.displayName
        }

    private fun applyStatic(
        decl: SymbolDecl.StaticVar,
        rawAddr: Long,
        typeRegistry: TypeRegistry,
    ): Boolean {
        val addr =
            ctx.program.addressFactory.defaultAddressSpace
                .getAddress(rawAddr)
        val dt = typeRegistry.dataTypeFor(decl.type) ?: return false
        try {
            // Clear any existing code units before creating data to avoid conflicts
            ctx.program.listing.clearCodeUnits(addr, addr.add((dt.length - 1).toLong()), false)
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
        val scopeBrackets: MutableList<Triple<StabType, Long, Int>>,
        var sizeBytes: Long = 0L,
    )

    internal data class ParamRecord(
        val decl: SymbolDecl,
        val rawValue: Long,
    )

    internal data class ApplyResult(
        val functions: Int,
        val globals: Int,
        val classes: Int = 0,
    )
}
