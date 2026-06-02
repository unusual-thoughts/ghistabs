package ghistabs.importer

import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.LocalVariableImpl
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.SourceType
import ghistabs.builder.Attribution
import ghistabs.builder.TypeRegistry
import ghistabs.diag.ApplyErrorBucket
import ghistabs.parser.*

class StabsImporter(internal val ctx: ImportContext<*>) : LogSink {
    override fun log(tag: String, message: String) = ctx.sink.log(tag, message)

    fun run(): PassResult {
        val readerResult = StabReader.fromProgram(ctx.program)
        if (readerResult == null) {
            ctx.sink.log("no-stabs", "No .stab/.stabstr block found; skipping import.")
            ctx.diagnostics.writeSummary(ctx.sink)
            return PassResult()
        }

        return runOnRecords(readerResult)
    }

    internal fun runOnRecords(stabs: StabReader.Result): PassResult {
        ctx.monitor.initialize(stabs.records.size.toLong())
        ctx.monitor.message = "Stabs: parsing"

        // Pass A — parse + harvest
        val harvester = Harvester(ctx.monitor, ctx.sink, ctx.resolver)
        val harvest = harvester.passA(stabs.records)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(ctx.dtm, ctx.sink, ctx.diagnostics)
        typeRegistry.setIncludeContexts(harvester.includesByFile)
        val txB = ctx.program.startTransaction("Stabs: materialise types")
        try {
            typeRegistry.materialiseAll(harvest.typeAstsById) { name, cus ->
                Attribution.categoryFor(name, cus, ctx.diagnostics)
            }
        } finally {
            ctx.program.endTransaction(txB, true)
        }

        // Pass C — apply symbols
        val txC = ctx.program.startTransaction("Stabs: apply symbols")
        val applyResult =
            try {
                applyAllSymbols(harvest, typeRegistry)
            } finally {
                ctx.program.endTransaction(txC, true)
            }

        // Emit end-of-run diagnostics summary
        ctx.diagnostics.writeSummary(ctx.sink)

        return PassResult(
            recordsRead = stabs.recordCount,
            recordsParsed = stabs.records.size - harvest.parseErrors,
            parseErrors = harvest.parseErrors,
            typesMaterialised = harvest.typeAsts.size,
            functionsApplied = applyResult.functions,
            globalsApplied = applyResult.globals,
            classesApplied = applyResult.classes,
        )
    }

    internal fun applyAllSymbols(harvest: Harvest, typeRegistry: TypeRegistry): ApplyResult {
        val source = SourceType.IMPORTED
        val funcMgr = ctx.program.functionManager
        var functions = 0
        var globals = 0
        var classes = 0

        // Run demangler stub replacement before applying symbols
        DemanglerReplacer(ctx, typeRegistry).run()

        for (open in harvest.openFunctions) {
            try {
                val func = funcMgr.getFunctionAt(open.addr.address)
                    ?: funcMgr.getFunctionContaining(open.addr.address)?.also {
                        ctx.diagnostics.inc("entrypoint-snapped")
                    }
                    ?: run {
                        ctx.diagnostics.inc("apply-error-no-function")
                        ctx.sink.log(
                            "apply-error-no-function",
                            "no Function at or containing ${open.addr} for ${open.name}",
                        )
                        continue
                    }

                // Apply return type from the parsed signature.
                val retDt = typeRegistry.dataTypeFor(open.decl.signature)
                if (retDt != null) func.setReturnType(retDt, source)

                // Build parameters from the recorded N_PSYM / N_RSYM records.
                val params = open.params.mapIndexed { i, p ->
                    val pdecl = p.decl
                    val (pname, pdt) = when (pdecl) {
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
                val bucket = ApplyErrorBucket.bucket(t)
                ctx.diagnostics.recordApplyError(open.name, bucket, t.message.orEmpty())
                ctx.sink.log("apply-error-$bucket", "function ${open.name}: ${t.message}")
                ctx.sink.log("apply-error", "function ${open.name}: ${t.message}", open.addr.address)
            }
        }

        // Globals + file-statics.
        for ((cu, syms) in harvest.symbolsByCu) {
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
        analyzeBssCoverage(harvest)

        // Classes + vtables.
        if (ctx.options.applyVtables) {
            val classBuilder = ghistabs.builder.ClassBuilder(
                ctx.program,
                typeRegistry,
                ctx.resolver,
                ctx.sink,
                harvest.structAstsByName,
                harvest.typeAstsById,
                ctx,
            )
            for (ast in harvest.typeAsts) {
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

    private fun analyzeBssCoverage(harvest: Harvest) {
        val bssBlock = ctx.program.memory.getBlock(".bss") ?: return

        // Build list of harvested symbols with resolved addresses
        val harvestedAddrs = harvest.allHarvestedSymbols.mapNotNull {
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
                when (val result = BssCoverageDecision.classify(pureRange, harvestedAddrs)) {
                    is CoverageResult.NoCoverage ->
                        ctx.sink.log("stabs-no-coverage", "@ $addr..$rangeEnd: no stabs records cover this range")

                    is CoverageResult.Covered -> result.coverers.forEach {
                        ctx.sink.log("stabs-coverage", "@ $addr..$rangeEnd: covered by ${it.symbolName}")
                    }
                }
            }

            addr = addr.add(4)
        }
    }

    private fun applyLocal(func: Function, loc: LocalRecord, typeRegistry: TypeRegistry, source: SourceType) {
        val decl = loc.decl
        val dt = when (decl) {
            is SymbolDecl.StackLocal -> typeRegistry.dataTypeFor(decl.type) ?: Undefined4DataType.dataType
            is SymbolDecl.RegLocal -> typeRegistry.dataTypeFor(decl.type) ?: Undefined4DataType.dataType
            else -> return
        }
        try {
            when (decl) {
                is SymbolDecl.StackLocal -> {
                    val paramNames = func.parameters.map { it.name }.toSet()
                    val localNames = func.localVariables.map { it.name }.toSet()
                    when (LocalVarDedup.shouldSkipLocal(decl.name, paramNames, localNames)) {
                        SkipReason.DuplicateParamName -> {
                            ctx.diagnostics.inc("local-var-skipped-dup-param")
                            return // benign N_PSYM+N_LSYM 'this' duplication
                        }

                        SkipReason.DuplicateLocalName -> {
                            ctx.diagnostics.inc("local-var-skipped-dup-local")
                            return // flat-locals model can't disambiguate sibling scopes
                        }

                        null -> {}
                    }
                    val stackOffset = loc.rawValue.toInt()
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    ctx.diagnostics.inc("local-var-add-success")
                }

                is SymbolDecl.RegLocal -> ctx.sink.log(
                    "regparam-deferred",
                    "Register local '${decl.name}' in function deferred (register mapping not implemented)",
                )
            }
        } catch (e: Exception) {
            // local-var-error counter auto-bumps via BookmarkSink tag→counter contract
            ctx.sink.log("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}")
        }
    }

    private fun applyScopeComments(func: Function, open: OpenFunction) {
        // Pair LBRAC (open) with matching RBRAC (close). For each pair, list
        // the locals whose record appears inside the bracket range and
        // attach a plate comment at the LBRAC address.
        val pairs = ScopePairs.compute(open.scopeBrackets, open.locals)
        for ((openOff, _, localsInScope) in pairs) {
            try {
                val addr = func.entryPoint.add(openOff)

                // Suppress empty scope comments (when a scope contains no locals).
                if (localsInScope.isEmpty()) {
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

    private fun applyGlobal(decl: SymbolDecl.Global, typeRegistry: TypeRegistry): Boolean {
        val addr = ctx.resolver.resolve(decl.name) ?: run {
            ctx.sink.log("unresolved-symbol", "global ${decl.name}")
            ctx.diagnostics.recordGlobal(decl.name, "skipped", dtKind = "unknown", reason = "unresolved-symbol")
            return false
        }
        val dt = typeRegistry.dataTypeFor(decl.type) ?: run {
            ctx.diagnostics.recordGlobal(
                addr.toString(),
                "skipped",
                dtKind = "unknown",
                reason = "no-resolved-type",
            )
            return false
        }
        val dtKind = when (dt) {
            is ghidra.program.model.data.Structure -> "Structure"
            is ghidra.program.model.data.Union -> "Union"
            is ghidra.program.model.data.Array -> "Array"
            is ghidra.program.model.data.Pointer -> "Pointer"
            is ghidra.program.model.data.FunctionDefinition -> "FunctionDefinition"
            is ghidra.program.model.data.Enum -> "Enum"
            else -> dt.displayName
        }
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

    private fun applyStatic(decl: SymbolDecl.StaticVar, rawAddr: Long, typeRegistry: TypeRegistry): Boolean {
        val addr = ctx.resolver.buildAddress(rawAddr)
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

    internal data class ApplyResult(val functions: Int, val globals: Int, val classes: Int = 0)
}
