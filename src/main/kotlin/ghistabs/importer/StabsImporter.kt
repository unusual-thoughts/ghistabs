package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.LocalVariableImpl
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.SourceType
import ghistabs.builder.Attribution
import ghistabs.builder.TypeRegistry
import ghistabs.diag.ApplyErrorBucket
import ghistabs.diag.DiagnosticSink
import ghistabs.parser.*

class StabsImporter(internal val ctx: ImportContext<*>) : DiagnosticSink by ctx.sink {
    fun run(): PassResult {
        val readerResult = StabReader.fromProgram(ctx.program)
        if (readerResult == null) {
            log("no-stabs", "No .stab/.stabstr block found; skipping import.")
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
        recordHarvestCounters(harvest, stabs)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(
            ctx.dtm,
            ctx.sink,
            ctx.diagnostics,
            harvest.fileResolver,
            harvest.typeResolver,
        )
        val txB = ctx.program.startTransaction("Stabs: materialise types")
        try {
            typeRegistry.materialiseAll(harvest.typeAsts) { name, cus ->
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

    /**
     * Surface harvest-side population sizes as counters so the end-of-run
     * `[diagnostics]` block answers "how much did we even see?" before any
     * apply-side filtering. Lets the user spot e.g. "we harvested 200 globals
     * but only applied 43" at a glance without running tooling.
     */
    private fun recordHarvestCounters(harvest: Harvest, stabs: StabReader.Result) {
        ctx.diagnostics.inc("harvest-records-read", stabs.recordCount.toLong())
        ctx.diagnostics.inc("harvest-records-parsed", (stabs.records.size - harvest.parseErrors).toLong())
        ctx.diagnostics.inc("harvest-parse-errors", harvest.parseErrors.toLong())
        ctx.diagnostics.inc("harvest-functions", harvest.openFunctions.size.toLong())
        val allSyms = harvest.symbolsByCu.values.flatten()
        ctx.diagnostics.inc("harvest-symbols", allSyms.size.toLong())
        ctx.diagnostics.inc("harvest-globals", allSyms.count { it.decl is SymbolDecl.Global }.toLong())
        ctx.diagnostics.inc("harvest-statics", allSyms.count { it.decl is SymbolDecl.StaticVar }.toLong())
        ctx.diagnostics.inc("harvest-typeAsts", harvest.typeAsts.size.toLong())
        // typeAst breakdown by AST kind — surfaces struct/enum/typedef weights.
        val byKind = harvest.typeAsts.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
        for ((kind, n) in byKind.toSortedMap()) {
            ctx.diagnostics.inc("harvest-typeAsts-$kind", n.toLong())
        }
        // Per-CU count of harvested symbols — top contributors land in the
        // examples bucket so a single huge CU is visible.
        ctx.diagnostics.inc("harvest-cus", harvest.symbolsByCu.size.toLong())
        // Names dropped during harvest (parse error or canonicalisation
        // collision) versus what reached PassA's output.
        val uniqueTypeIds = harvest.typeAsts.map { it.id }.toSet().size
        ctx.diagnostics.inc("harvest-typeAsts-unique-by-id", uniqueTypeIds.toLong())
        ctx.diagnostics.inc("harvest-typeAsts-dup-by-id", (harvest.typeAsts.size - uniqueTypeIds).toLong())
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
                    ?: tryCreateFunctionFromStab(open) ?: run {
                    ctx.diagnostics.inc("apply-error-no-function")
                    log(
                        "apply-error-no-function",
                        "no Function at or containing ${open.addr} for ${open.name}",
                    )
                    continue
                }

                // Apply return type from the parsed signature.
                val retDt = typeRegistry.dataTypeFor(open.decl.type, open.cu)
                if (retDt != null) func.setReturnType(retDt, source)

                // Build parameters from the recorded N_PSYM / N_RSYM records.
                //
                // Filter out any N_PSYM literally named `this`: gcc 3.x emits
                // `this` as the first N_PSYM for member functions but often
                // mistypes it (we've seen `int` instead of `<Class>*`). The
                // class-level pass (`ClassBuilder.reparentMethod`) will set
                // `__thiscall` and synthesise the typed `this` from the class
                // struct, which is the authoritative source — N_PSYM `this`
                // would only collide with that as a leftover slot Ghidra
                // can't always evict, producing duplicate-`this` signatures.
                val params = open.params
                    .filterNot {
                        val d = it.decl
                        (d is SymbolDecl.StackParam && d.name == "this") ||
                            (d is SymbolDecl.RegParam && d.name == "this")
                    }
                    .mapIndexed { i, p ->
                        val pdecl = p.decl
                        val (pname, pdt) = when (pdecl) {
                            is SymbolDecl.StackParam -> pdecl.name to typeRegistry.dataTypeFor(
                                pdecl.type,
                                open.cu,
                            )

                            is SymbolDecl.RegParam -> pdecl.name to typeRegistry.dataTypeFor(
                                pdecl.type,
                                open.cu,
                            )

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
                    applyLocal(open.cu, func, loc, typeRegistry, source)
                }

                // Apply scope plate comments.
                if (ctx.options.applyPlateComments) applyScopeComments(func, open)

                functions++
            } catch (t: Throwable) {
                val bucket = ApplyErrorBucket.bucket(t)
                ctx.diagnostics.recordApplyError(open.name, bucket, t.message.orEmpty())
                log("apply-error-$bucket", "function ${open.name}: ${t.message}")
                log("apply-error", "function ${open.name}: ${t.message}", open.addr.address)
            }
        }

        // Globals + file-statics.
        for ((cu, syms) in harvest.symbolsByCu) {
            for (h in syms) {
                try {
                    when (val d = h.decl) {
                        is SymbolDecl.Global -> applyGlobal(cu, d, typeRegistry).let { if (it) globals++ }
                        is SymbolDecl.StaticVar -> applyStatic(
                            cu,
                            d,
                            h.rawValue,
                            typeRegistry,
                        ).let { if (it) globals++ }

                        else -> {
                            log("unexpected-symbol", "$d")
                        }
                    }
                } catch (t: Throwable) {
                    log("apply-error", "symbol ${h.decl.name} in $cu: ${t.message}")
                }
            }
        }

        // .bss coverage analysis: detect uncovered ranges in the .bss section.
        analyzeBssCoverage(harvest)

        // Classes + vtables.
        if (ctx.options.applyVtables) {
            val classBuilder = ghistabs.builder.ClassBuilder(
                typeRegistry,
                harvest.typeResolver,
                ctx,
            )
            // Dedupe ASTs by name: many classes appear under multiple cuFiles (each transitive
            // include of a header that defines the class produces a TypeAst). materialiseAll
            // collapses them into one DataType keyed by the union of defining CUs; ClassBuilder
            // must use the same union for Attribution so its DTM lookup matches.
            // Dedupe ASTs by name and use the union of cuFiles for Attribution — the same
            // signal materialiseAll used when seeding placeholders. Per-AST iteration with
            // single-cuFile attribution produced N attempted `dtm.getDataType` lookups per
            // class, only ONE landing on the canonical category (huge `[class-not-struct]`
            // log spam). Pick the most-detailed body (max methods, then fields) so vtable
            // construction sees the full method list.
            for ((name, asts) in harvest.typeAsts.groupBy { it.name }) {
                val structAsts = asts.mapNotNull {
                    when (it.body) {
                        is TypeDecl.Struct -> it.cu to it.body
                        else -> null
                    }
                }.toMap()
                if (structAsts.isEmpty()) continue
                val (cu, body) = structAsts.maxWithOrNull(
                    compareBy(
                        { it.value.methods.size },
                        { it.value.fields.size },
                    ),
                )!!

                if (body.methods.isEmpty() && !body.hasVTablePointerMarker) continue
                try {
                    val defSources = asts.map { it.id.source }.toSet()
                    val category = Attribution.categoryFor(name, defSources, ctx.diagnostics)
                    classBuilder.build(cu, name, body, category)
                    classes++
                } catch (t: Throwable) {
                    log("class-apply-error", "$name: ${t.message}")
                }
            }
        }

        // Final pass: demangle any Itanium-mangled IMPORTED labels that remain.
        // Ghidra's DemanglerAnalyzer is a BYTE_ANALYZER that runs once at
        // priority ~897 over loader-added symbols; labels we created via
        // `recordFromStab` were not in that set and so were never demangled.
        // We replicate the analyzer's per-symbol invocation locally, with
        // signature/calling-convention application disabled — the stab has
        // richer signatures than the demangler could derive from the mangled
        // name, and our `__thiscall` choice (set in ClassBuilder) must win.
        demangleMangledLabels()

        return ApplyResult(functions, globals, classes)
    }

    private fun demangleMangledLabels() {
        val options = ghidra.app.util.demangler.DemanglerOptions().apply {
            setApplySignature(false)
            setApplyCallingConvention(false)
            setDoDisassembly(false)
        }
        var attempted = 0
        var demangled = 0
        for (sym in ctx.program.symbolTable.symbolIterator) {
            ctx.monitor.checkCancelled()
            val name = sym.name
            // Itanium-mangled symbols start with `_Z`; on Cygwin PE/COFF the
            // loader prepends an extra underscore, giving `__Z`. Either form
            // is handled by GnuDemangler (it strips a single leading `_`).
            if (!name.startsWith("_Z") && !name.startsWith("__Z")) continue
            attempted++
            val cmd = ghidra.app.cmd.label.DemanglerCmd(sym.address, name, options)
            if (cmd.applyTo(ctx.program, ctx.monitor) && cmd.result != null) {
                demangled++
            }
        }
        ctx.diagnostics.inc("demangle-attempted", attempted.toLong())
        ctx.diagnostics.inc("demangle-applied", demangled.toLong())
    }

    /**
     * The stab's N_FUN record asserts a function exists at this address but Ghidra's
     * auto-analysis didn't discover one (typical for ctors only called from data-driven
     * init lists like `__static_initialization_and_destruction_0`, or for functions
     * referenced only via vtable). Force-create the function — the stab is authoritative.
     * Returns the created Function or null if creation failed (e.g. address is in data).
     */
    private fun tryCreateFunctionFromStab(open: OpenFunction): Function? {
        val addr = open.addr.address
        val cmd = ghidra.app.cmd.function.CreateFunctionCmd(open.name, addr, null, SourceType.IMPORTED)
        if (!cmd.applyTo(ctx.program, ctx.monitor)) {
            return null
        }
        ctx.diagnostics.inc("function-created-from-stab")
        return ctx.program.functionManager.getFunctionAt(addr)
    }

    private fun analyzeBssCoverage(harvest: Harvest) {
        val bssBlock = ctx.program.memory.getBlock(".bss") ?: return

        // Build list of harvested symbols with resolved addresses
        val harvestedAddrs = harvest.allHarvestedSymbols.mapNotNull {
            val name = (it.decl as? SymbolDecl.Global)?.name ?: return@mapNotNull null
            val addr = ctx.resolver.resolve(name)?.offset
            HarvestedAddr(name, addr)
        }

        // Scan .bss block at 4-byte intervals, accumulating contiguous no-coverage runs
        // into a single log entry per range (otherwise a typical .bss produces thousands
        // of one-per-chunk lines).
        var addr = bssBlock.start
        var gapStart: Address? = null
        var gapEnd: Address? = null

        fun flushGap() {
            val start = gapStart ?: return
            val end = gapEnd ?: return
            log(
                "stabs-no-coverage",
                "@ $start..$end (${end.offset - start.offset + 1} bytes): no stabs records cover this range",
            )
            gapStart = null
            gapEnd = null
        }

        while (addr <= bssBlock.end) {
            ctx.monitor.checkCancelled()
            val rangeEnd = addr.add(3)

            val occupied = ctx.program.symbolTable.getPrimarySymbol(addr) != null ||
                ctx.program.listing.getDefinedDataAt(addr) != null
            if (occupied) {
                flushGap()
            } else {
                val pureRange = AddrRange(addr.offset, rangeEnd.offset)
                when (val result = BssCoverageDecision.classify(pureRange, harvestedAddrs)) {
                    is CoverageResult.NoCoverage -> {
                        if (gapStart == null) gapStart = addr
                        gapEnd = rangeEnd
                    }

                    is CoverageResult.Covered -> {
                        flushGap()
                        result.coverers.forEach {
                            log("stabs-coverage", "@ $addr..$rangeEnd: covered by ${it.symbolName}")
                        }
                    }
                }
            }

            addr = addr.add(4)
        }
        flushGap()
    }

    private fun applyLocal(
        cu: SourceFile.CUSource,
        func: Function,
        loc: LocalRecord,
        typeRegistry: TypeRegistry,
        source: SourceType,
    ) {
        val decl = loc.decl
        val dt = when (decl) {
            is SymbolDecl.StackLocal -> typeRegistry.dataTypeFor(decl.type, cu)
            is SymbolDecl.RegLocal -> typeRegistry.dataTypeFor(decl.type, cu)
            else -> return
        } ?: Undefined4DataType.dataType
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

                is SymbolDecl.RegLocal -> log(
                    "regparam-deferred",
                    "Register local '${decl.name}' in function deferred (register mapping not implemented)",
                )
            }
        } catch (e: Exception) {
            // local-var-error counter auto-bumps via BookmarkSink tag→counter contract
            log("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}")
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
                log("scope-comment-error", "Failed to set scope comment: ${e.message}")
            }
        }
    }

    private fun applyGlobal(cu: String, decl: SymbolDecl.Global<GlobalTypeId>, typeRegistry: TypeRegistry): Boolean {
        val addr = ctx.resolver.resolve(decl.name) ?: run {
            log("unresolved-symbol", "global ${decl.name}")
            ctx.diagnostics.recordGlobal(decl.name, "skipped", dtKind = "unknown", reason = "unresolved-symbol")
            return false
        }
        if (decl.name == "ExpressionStrings") {

        val dt = typeRegistry.dataTypeFor(decl.type, SourceFile.CUSource(cu)) ?: run {
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
        // Use ClearDataMode.CLEAR_ALL_CONFLICT_DATA (via DataUtilities) to
        // forcibly evict any existing data in the range — including
        // `undefined4` placeholders that auto-analysis raced us to apply
        // in CONCURRENT mode. `Listing.clearCodeUnits` alone is enough in
        // single-threaded transactional code, but the helper is explicit
        // about its conflict resolution.
        try {
            ghidra.program.model.data.DataUtilities.createData(
                ctx.program,
                addr,
                dt,
                dt.length,
                ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
            // Verify our type actually stuck. If Ghidra (auto-analyser racing
            // us, undo path, or data-equivalence collapse) replaced what we
            // wrote with something else, surface it loudly via a per-kind
            // counter rather than silently claiming success.
            val after = ctx.program.listing.getDataAt(addr)
            val stuck = after != null && after.dataType.name == dt.name
            if (!stuck) {
                ctx.diagnostics.inc("global-applied-then-overwritten")
                log(
                    "global-applied-then-overwritten",
                    "$decl.name at $addr: wrote ${dt.name} but readback is ${after?.dataType?.name}",
                )
            }
            ctx.diagnostics.recordGlobal(addr.toString(), "applied", dtKind = dtKind)
        } catch (e: Exception) {
            log("apply-error", "Failed to create global data at $addr: ${e.message}")
            ctx.diagnostics.recordGlobal(addr.toString(), "skipped", dtKind = dtKind, reason = "create-data-failed")
            return false
        }
        return true
    }

    private fun applyStatic(
        cu: String,
        decl: SymbolDecl.StaticVar<GlobalTypeId>,
        rawAddr: Long,
        typeRegistry: TypeRegistry,
    ): Boolean {
        val addr = ctx.resolver.buildAddress(rawAddr)
        val dt = typeRegistry.dataTypeFor(decl.type, SourceFile.CUSource(cu)) ?: return false

        try {
            // Clear any existing code units before creating data to avoid conflicts
            ctx.program.listing.clearCodeUnits(addr, addr.add((dt.length - 1).toLong()), false)
            ctx.program.listing.createData(addr, dt)
        } catch (e: Exception) {
            log("apply-error", "Failed to create static data at $addr: ${e.message}")
            return false
        }
        return true
    }

    internal data class ApplyResult(val functions: Int, val globals: Int, val classes: Int = 0)
}
