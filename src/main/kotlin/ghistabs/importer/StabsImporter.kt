package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.LocalVariableImpl
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.SourceType
import ghistabs.diagnose.ApplyErrorBucket
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.isInlineStdMember
import ghistabs.harvest.*
import ghistabs.materialize.TypeRegistry
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabReader
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import ghistabs.runTransaction

private val X86_DBX_TO_REGISTER = listOf("EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI")
private val X86_64_DBX_TO_REGISTER = listOf(
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
)

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
        // TypeResolver adds by-name/by-XRef indices + canonicalisation + divergent-collision filter.
        val typeResolver = TypeResolver(harvest.typeAsts, harvest.rawCollisions, ctx.sink, ctx.diagnostics)
        recordHarvestCounters(harvest, typeResolver, stabs)

        // Pass B — materialise types
        val typeRegistry = TypeRegistry(
            ctx.dtm,
            ctx.sink,
            ctx.diagnostics,
            harvest,
            typeResolver,
        )

        ctx.program.runTransaction("Stabs: materialise types") {
            typeRegistry.materialiseAll()
        }

        // Pass C — apply symbols
        val applyResult = ctx.program.runTransaction("Stabs: apply symbols") {
            applyAllSymbols(harvest, typeRegistry, typeResolver)
        }

        // Flag never-materialised placeholders — they cause "Offset 0 beyond end of structure"
        // cascades downstream; naming them at source makes the root cause findable.
        typeRegistry.reportSurvivingPlaceholders()

        // Emit end-of-run diagnostics summary
        ctx.diagnostics.writeSummary(ctx.sink)
        if (ctx.options.logDegradations) {
            ctx.diagnostics.writeDegradations(ctx.sink)
        }

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

    private fun recordHarvestCounters(harvest: Harvest, resolver: TypeResolver, stabs: StabReader.Result) {
        ctx.diagnostics.inc("harvest-records-read", stabs.recordCount.toLong())
        ctx.diagnostics.inc("harvest-records-parsed", (stabs.records.size - harvest.parseErrors).toLong())
        ctx.diagnostics.inc("harvest-parse-errors", harvest.parseErrors.toLong())
        ctx.diagnostics.inc("harvest-functions", harvest.openFunctions.size.toLong())
        val allSyms = harvest.symbolsByCu.values.flatten()
        ctx.diagnostics.inc("harvest-symbols", allSyms.size.toLong())
        ctx.diagnostics.inc("harvest-globals", allSyms.count { it.body is SymbolDecl.Global }.toLong())
        ctx.diagnostics.inc("harvest-statics", allSyms.count { it.body is SymbolDecl.StaticVar }.toLong())
        ctx.diagnostics.inc("harvest-typeAsts", harvest.typeAsts.size.toLong())
        val byKind = harvest.typeAsts.values.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
        for ((kind, n) in byKind.toSortedMap()) {
            ctx.diagnostics.inc("harvest-typeAsts-$kind", n.toLong())
        }
        ctx.diagnostics.inc("harvest-cus", harvest.symbolsByCu.size.toLong())
        val uniqueTypeIds = harvest.typeAsts.keys.size
        ctx.diagnostics.inc("harvest-typeAsts-unique-by-id", uniqueTypeIds.toLong())
        ctx.diagnostics.inc("harvest-typeAsts-dup-by-id", (harvest.typeAsts.size - uniqueTypeIds).toLong())
        ctx.diagnostics.inc("harvest-collisions-raw", harvest.rawCollisions.size.toLong())
        ctx.diagnostics.inc(
            "harvest-collisions-raw-total",
            harvest.rawCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
        // Post-filter: content-equivalent dups dropped, only genuinely divergent collisions remain.
        ctx.diagnostics.inc("harvest-collisions-divergent", resolver.divergentCollisions.size.toLong())
        ctx.diagnostics.inc(
            "harvest-collisions-divergent-total",
            resolver.divergentCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
    }

    internal fun applyAllSymbols(
        harvest: Harvest,
        typeRegistry: TypeRegistry,
        typeResolver: TypeResolver,
    ): ApplyResult {
        val source = SourceType.IMPORTED
        val funcMgr = ctx.program.functionManager
        var functions = 0
        var globals = 0
        var classes = 0

        for (open in harvest.openFunctions) {
            try {
                val func = funcMgr.getFunctionAt(open.addr.address)
                    ?: funcMgr.getFunctionContaining(open.addr.address)?.also {
                        ctx.diagnostics.inc("entrypoint-snapped")
                    }
                    ?: tryCreateFunctionFromStab(open) ?: run {
                    val tag: String
                    val level: Level
                    if (isInlineStdMember(open.name)) {
                        tag = "apply-error-inlined-std"
                        level = Level.DEBUG
                    } else {
                        tag = "apply-error-no-function"
                        level = Level.INFO
                    }
                    // BookmarkSink auto-bumps the counter on log() — no explicit inc.
                    log(tag, "no Function at or containing ${open.addr} for ${open.name}", level)
                    continue
                }

                // Apply return type from the parsed signature.
                val retDt = typeRegistry.dataTypeFor(open.decl.type)
                if (retDt != null) func.setReturnType(retDt, source)

                // Drop any N_PSYM `this` — gcc 3.x often mistypes it (e.g. int instead of Class*),
                // and ClassBuilder.reparentMethod will synthesise a typed `this` from the class struct.
                val params = open.params
                    .filterNot {
                        val d = it.body
                        (d is SymbolDecl.StackParam && d.name == "this") ||
                            (d is SymbolDecl.RegParam && d.name == "this")
                    }
                    .mapIndexed { i, p ->
                        val pdecl = p.body
                        val (pname, pdt) = when (pdecl) {
                            is SymbolDecl.StackParam -> pdecl.name to typeRegistry.dataTypeFor(pdecl.type)
                            is SymbolDecl.RegParam -> pdecl.name to typeRegistry.dataTypeFor(pdecl.type)
                            else -> "arg$i" to null
                        }
                        if (pdt == null) {
                            ctx.diagnostics.recordDegradation(
                                "param-untyped",
                                "${open.name}.$pname",
                            )
                        }
                        ParameterImpl(
                            pname,
                            pdt ?: Undefined4DataType.dataType,
                            ctx.program,
                            source,
                        )
                    }
                // Always replace (even empty) — leaves Ghidra's auto-guessed signature out.
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
                log("apply-error-$bucket", "function ${open.name}: ${t.message}")
                log("apply-error", "function ${open.name}: ${t.message}", address = open.addr.address)
            }
        }

        // Globals + file-statics.
        for ((cu, syms) in harvest.symbolsByCu) {
            for (h in syms) {
                try {
                    when (val d = h.body) {
                        is SymbolDecl.Global -> applyGlobal(d, typeRegistry).let { if (it) globals++ }

                        is SymbolDecl.StaticVar -> applyStatic(d, h.rawValue, typeRegistry).let {
                            if (it) globals++
                        }

                        else -> log("unexpected-symbol", "$d")
                    }
                } catch (t: Throwable) {
                    log("apply-error", "symbol ${h.body.name} in $cu: ${t.message}")
                }
            }
        }

        // .bss coverage analysis: detect uncovered ranges in the .bss section.
        analyzeBssCoverage(harvest)

        // Classes + vtables. typeResolver.byCanonicalKey collapsed same-name TypeAsts to one entry
        // per (category, name); we just iterate them.
        if (ctx.options.applyVtables) {
            val classBuilder = ghistabs.materialize.ClassBuilder(typeRegistry, harvest, typeResolver, ctx)
            ctx.diagnostics.inc(
                "class-build-name-collisions",
                harvest.typeAsts.values.groupingBy { it.ghidraName }.eachCount()
                    .values.count { it > 1 }.toLong(),
            )
            for (group in typeResolver.byCanonicalKey.values) {
                if (group.ast.body !is TypeDecl.Struct) {
                    continue
                }

                // gcc 12 emits the vfptr as a regular `_vptr.X` field, not the `~%<id>;` marker —
                // treat any `_vptr*` field as the polymorphic-class signal.
                val hasVptrField = group.ast.body.fields.any {
                    it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr"
                }
                if (group.ast.body.methods.isEmpty() &&
                    !group.ast.body.hasVTablePointerMarker &&
                    !hasVptrField
                ) {
                    continue
                }
                try {
                    classBuilder.build(group)
                    classes++
                } catch (t: Throwable) {
                    log("class-apply-error", "${group.key}: ${t.message}")
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

        // DemanglerReplacer scans `/Demangler/*` stubs and substitutes any
        // matching stab-sourced type with the same simple name. Must run
        // AFTER demangleMangledLabels so every `/Demangler/...` placeholder
        // created during signature demangling is visible to the scan.
        DemanglerReplacer(ctx, typeRegistry).run()

        // Surface the populated TypeRegistry for tests (see ImportContext kdoc).
        ctx.typeRegistry = typeRegistry

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
            // `__Z` is Cygwin PE/COFF's extra-underscore form; GnuDemangler strips it.
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
     * Force-create the function the N_FUN record asserts when autoanalysis missed it (typical for
     * vtable-only or static-init-list referenced functions). Returns null on creation failure.
     */
    private fun tryCreateFunctionFromStab(open: OpenFunction): Function? {
        val addr = open.addr.address
        val block = ctx.program.memory.getBlock(addr)
        if (block == null || !block.isExecute) {
            // Inline std::/__gnu_cxx members get stabs but no .text (inlined+COMDAT-dropped); demote.
            val inlined = isInlineStdMember(open.name)
            val tag = if (inlined) "function-create-inlined-std" else "function-create-skipped-non-text"
            val level = if (inlined) Level.DEBUG else Level.WARN
            log(tag, "no executable block at $addr for ${open.name} (block=${block?.name})", level)
            return null
        }

        // CreateFunctionCmd needs an Instruction to anchor on — disassemble first if missing.
        if (ctx.program.listing.getInstructionAt(addr) == null) {
            val disasm = ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true)
            if (disasm.applyTo(ctx.program, ctx.monitor) && disasm.disassembledAddressSet.numAddresses > 0) {
                ctx.diagnostics.inc("function-create-disassembled-first")
            } else {
                log(
                    "function-create-disasm-failed",
                    "DisassembleCommand failed at $addr for ${open.name}: ${disasm.statusMsg}",
                    Level.WARN,
                )
                return null
            }
        }

        val cmd = ghidra.app.cmd.function.CreateFunctionCmd(open.name, addr, null, SourceType.IMPORTED)
        if (!cmd.applyTo(ctx.program, ctx.monitor)) {
            log(
                "function-create-cmd-failed",
                "CreateFunctionCmd failed at $addr for ${open.name}: ${cmd.statusMsg}",
                Level.WARN,
            )
            return null
        }
        ctx.diagnostics.inc("function-created-from-stab")
        return ctx.program.functionManager.getFunctionAt(addr)
    }

    private fun analyzeBssCoverage(harvest: Harvest) {
        val bssBlock = ctx.program.memory.getBlock(".bss") ?: return

        // Build list of harvested symbols with resolved addresses
        val harvestedAddrs = harvest.allHarvestedSymbols.mapNotNull {
            val name = (it.body as? SymbolDecl.Global)?.name ?: return@mapNotNull null
            val addr = ctx.resolver.resolve(name)?.offset
            HarvestedAddr(name, addr)
        }

        // Scan .bss at 4-byte intervals; coalesce contiguous no-coverage runs into one log line.
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

    /**
     * Map gcc dbx register number → Ghidra register name (i386 and x86_64 only; per
     * gcc/config/<arch>/<arch>.h `DBX_REGISTER_NUMBER`).
     */
    private fun dbxRegisterName(dbxNum: Int): String? {
        val table = when (ctx.program.defaultPointerSize) {
            4 -> X86_DBX_TO_REGISTER
            8 -> X86_64_DBX_TO_REGISTER
            else -> return null
        }
        return table.getOrNull(dbxNum)
    }

    private fun applyLocal(func: Function, loc: SymbolRecord, typeRegistry: TypeRegistry, source: SourceType) {
        val decl = loc.body
        val resolvedDt = when (decl) {
            is SymbolDecl.StackLocal -> typeRegistry.dataTypeFor(decl.type)
            is SymbolDecl.RegLocal -> typeRegistry.dataTypeFor(decl.type)
            else -> return
        }
        if (resolvedDt == null) {
            ctx.diagnostics.recordDegradation("local-untyped", "${func.name}.${decl.name}]")
        }
        val dt = resolvedDt ?: Undefined4DataType.dataType
        try {
            when (decl) {
                is SymbolDecl.StackLocal -> {
                    if (decl.name in func.parameters.map { it.name }) {
                        ctx.diagnostics.inc("local-var-skipped-dup-param")
                        return
                    }
                    if (decl.name in func.localVariables.map { it.name }) {
                        ctx.diagnostics.inc("local-var-skipped-dup-local")
                        return
                    }
                    val stackOffset = loc.rawValue.toInt()
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    ctx.diagnostics.inc("local-var-add-success")
                }

                is SymbolDecl.RegLocal -> {
                    val regName = dbxRegisterName(decl.regNum)
                    val reg = regName?.let { ctx.program.getRegister(it) }
                    if (reg == null) {
                        ctx.diagnostics.recordDegradation(
                            "reglocal-unmapped-regnum",
                            "${func.name}.${decl.name}",
                            "dbx-reg=${decl.regNum} arch-ptr-size=${ctx.program.defaultPointerSize}",
                        )
                        return
                    }
                    if (decl.name in func.parameters.map { it.name }) {
                        ctx.diagnostics.inc("reglocal-skipped-dup-param")
                        return
                    }
                    if (decl.name in func.localVariables.map { it.name }) {
                        ctx.diagnostics.inc("reglocal-skipped-dup-local")
                        return
                    }
                    val lv = LocalVariableImpl(decl.name, 0, dt, reg, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    ctx.diagnostics.inc("reglocal-add-success")
                }
            }
        } catch (e: Exception) {
            // local-var-error counter auto-bumps via BookmarkSink tag→counter contract
            log("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}")
        }
    }

    private fun applyScopeComments(func: Function, open: OpenFunction) {
        // For each LBRAC/RBRAC pair, plate-comment the locals declared inside at the LBRAC address.
        val pairs = ScopePairs.compute(open.scopeBrackets, open.locals)
        for ((openOff, _, localsInScope) in pairs) {
            try {
                val addr = func.entryPoint.add(openOff)

                // Suppress empty scope comments (when a scope contains no locals).
                if (localsInScope.isEmpty()) {
                    ctx.diagnostics.recordEmptyScope(addr.toString(), func.name)
                    continue
                }
                val text = "Stabs scope locals: " + localsInScope.joinToString(", ") { it.body.name }
                ctx.program.listing.setComment(addr, CommentType.PLATE, text)
            } catch (e: Exception) {
                log("scope-comment-error", "Failed to set scope comment: ${e.message}")
            }
        }
    }

    private fun applyGlobal(decl: SymbolDecl.Global<GlobalTypeId>, typeRegistry: TypeRegistry): Boolean {
        val addr = ctx.resolver.resolve(decl.name) ?: run {
            log("unresolved-symbol", "global ${decl.name}", Level.WARN)
            ctx.diagnostics.recordGlobal(decl.name, "skipped", dtKind = "unknown", reason = "unresolved-symbol")
            return false
        }
        ensureStabLabel(addr, decl.name)

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
        // CLEAR_ALL_CONFLICT_DATA evicts undefined4 placeholders autoanalysis raced us to apply.
        try {
            ghidra.program.model.data.DataUtilities.createData(
                ctx.program,
                addr,
                dt,
                dt.length,
                ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
            // Verify our type stuck — auto-analyser races / undo path can overwrite silently.
            val after = ctx.program.listing.getDataAt(addr)
            val stuck = after != null && after.dataType.name == dt.name
            if (!stuck) {
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
        decl: SymbolDecl.StaticVar<GlobalTypeId>,
        rawAddr: Long,
        typeRegistry: TypeRegistry,
    ): Boolean {
        val addr = ctx.resolver.buildAddress(rawAddr)
        val dt = typeRegistry.dataTypeFor(decl.type) ?: return false
        ensureStabLabel(addr, decl.name)

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

    /**
     * Make [name] primary at [addr] — otherwise globals keep the PE loader's `_<name>` label
     * and the demangled form never appears in the symbol table. Idempotent.
     */
    private fun ensureStabLabel(addr: Address, name: String) {
        val symtab = ctx.program.symbolTable
        val existing = symtab.getSymbols(addr).firstOrNull { it.name == name }
        val sym = existing ?: try {
            symtab.createLabel(addr, name, SourceType.IMPORTED)
        } catch (e: Exception) {
            log("symbol-create-error", "$name at $addr: ${e.message}")
            return
        }
        if (!sym.isPrimary) {
            try {
                ghidra.app.cmd.label.SetLabelPrimaryCmd(addr, sym.name, sym.parentNamespace)
                    .applyTo(ctx.program)
            } catch (e: Exception) {
                log("symbol-primary-error", "$name at $addr: ${e.message}")
            }
        }
    }

    internal data class ApplyResult(val functions: Int, val globals: Int, val classes: Int = 0)
}
