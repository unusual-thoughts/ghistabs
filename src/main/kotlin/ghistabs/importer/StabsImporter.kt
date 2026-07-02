package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghistabs.applyDemangling
import ghistabs.diagnose.ApplyErrorBucket
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.harvest.*
import ghistabs.materialize.TypeRegistry
import ghistabs.materialize.TypedefShortener
import ghistabs.parse.*
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
        // Resolver: by-name/by-base-tag indices, canonicalization, divergent-collision
        // filtering. Every cross-CU lookup downstream goes through this.
        val typeResolver = TypeResolver(harvest, ctx.sink)
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
            if (ctx.options.shortenTypedefs) TypedefShortener(ctx.dtm, ctx.sink).apply()
        }

        // Pass C — apply symbols
        val applyResult = ctx.program.runTransaction("Stabs: apply symbols") {
            applyAllSymbols(harvest, typeRegistry, typeResolver)
        }

        typeRegistry.reportSurvivingPlaceholders()

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
        log("harvest-records-read", count = stabs.recordCount.toLong())
        log("harvest-records-parsed", count = (stabs.records.size - harvest.parseErrors).toLong())
        log("harvest-parse-errors", count = harvest.parseErrors.toLong())
        log("harvest-functions", count = harvest.openFunctions.size.toLong())
        val allSyms = harvest.symbolsByCu.values.flatten()
        log("harvest-symbols", count = allSyms.size.toLong())
        log("harvest-globals", count = allSyms.count { it.body is SymbolDecl.Global }.toLong())
        log("harvest-statics", count = allSyms.count { it.body is SymbolDecl.StaticVar }.toLong())
        log("harvest-typeAsts", count = harvest.typeAsts.size.toLong())
        val byKind = harvest.typeAsts.values.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
        for ((kind, n) in byKind.toSortedMap()) {
            log("harvest-typeAsts-$kind", count = n.toLong())
        }
        log("harvest-cus", count = harvest.symbolsByCu.size.toLong())
        val uniqueTypeIds = harvest.typeAsts.keys.size
        log("harvest-typeAsts-unique-by-id", count = uniqueTypeIds.toLong())
        log("harvest-typeAsts-dup-by-id", count = (harvest.typeAsts.size - uniqueTypeIds).toLong())
        log("harvest-collisions-raw", count = harvest.rawCollisions.size.toLong())
        log(
            "harvest-collisions-raw-total",
            count = harvest.rawCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
        // Post-filter: only genuinely divergent multi-body collisions.
        log("harvest-collisions-divergent", count = resolver.divergentCollisions.size.toLong())
        log(
            "harvest-collisions-divergent-total",
            count = resolver.divergentCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
    }

    internal fun applyAllSymbols(
        harvest: Harvest,
        typeRegistry: TypeRegistry,
        typeResolver: TypeResolver,
    ): ApplyResult {
        val source = SourceType.IMPORTED
        val funcMgr = ctx.program.functionManager
        val frameBias = deriveStackFrameBias(harvest)
        var functions = 0
        var globals = 0
        var classes = 0

        for (open in harvest.openFunctions) {
            try {
                val func = funcMgr.getFunctionAt(open.addr.address)
                    ?: funcMgr.getFunctionContaining(open.addr.address)?.also {
                        log("entrypoint-snapped")
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

                // Build params from N_PSYM/N_RSYM. Filter out any N_PSYM literally named
                // `this`: gcc 3.x emits it for members but often mistypes (seen `int`
                // instead of `<Class>*`); ClassBuilder.reparentMethod sets __thiscall and
                // synthesises a typed `this` from the class struct, which is authoritative.
                // Keeping the N_PSYM one produces duplicate-`this` signatures Ghidra can't evict.
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
                        typeRegistry.reasonFor(pdt)?.let { reason ->
                            ctx.diagnostics.recordDegradation(
                                "param-typed-$reason",
                                "${open.name}.$pname",
                                "type=${pdt?.pathName}",
                            )
                        }
                        ParameterImpl(
                            pname,
                            pdt ?: Undefined4DataType.dataType,
                            ctx.program,
                            source,
                        )
                    }
                // Always replace (even empty list) to set the signature explicitly.
                func.replaceParameters(
                    params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    true,
                    source,
                )

                // Apply locals.
                for (loc in open.locals) {
                    applyLocal(func, loc, typeRegistry, source, frameBias)
                }

                // Apply scope plate comments.
                if (ctx.options.applyPlateComments) applyScopeComments(func, open)

                functions++
            } catch (t: Throwable) {
                val bucket = ApplyErrorBucket.bucket(t)
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

        analyzeBssCoverage(harvest)

        // Classes + vtables. Each class header included by N CUs produces N TypeAsts with
        // distinct ids but identical ghidraName (xapasmcsr: 86 names duplicated up to 11x).
        // materialiseAll already collapsed by name; iterating canonical groups here ensures
        // we build each class once, off the most-detailed body.
        if (ctx.options.applyVtables) {
            val classBuilder = ghistabs.materialize.ClassBuilder(typeRegistry, harvest, typeResolver, ctx)
            log(
                "class-build-name-collisions",
                count = harvest.typeAsts.values.groupingBy { it.ghidraName }.eachCount()
                    .values.count { it > 1 }.toLong(),
            )
            for (group in typeResolver.byCanonicalKey.values) {
                if (group.ast.body !is TypeDecl.Struct) {
                    continue
                }

                // gcc 12 emits the vfptr as a regular `_vptr.XX` field instead of the
                // `~%<id>;` marker hasVTablePointerMarker watches for — without this check
                // every polymorphic class in xmltest would be skipped.
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

        // Ghidra's DemanglerAnalyzer is a BYTE_ANALYZER that only runs over loader-added
        // symbols, missing labels we created via recordFromStab. Replicate it locally with
        // signature/calling-convention application off — stab signatures are richer and
        // our __thiscall must win.
        demangleMangledLabels()

        // Must run AFTER demangleMangledLabels so every /Demangler/... stub created during
        // signature demangling is visible to the scan.
        DemanglerReplacer(ctx, typeRegistry).run()

        ctx.typeRegistry = typeRegistry
        ctx.typeResolver = typeResolver

        return ApplyResult(functions, globals, classes)
    }

    private fun demangleMangledLabels() {
        var attempted = 0
        var demangled = 0
        for (sym in ctx.program.symbolTable.symbolIterator) {
            ctx.monitor.checkCancelled()
            val name = sym.name
            // Cygwin PE/COFF loader prepends `_`, so Itanium symbols appear as `__Z`.
            // GnuDemangler handles both (strips one leading `_`).
            if (!name.startsWith("_Z") && !name.startsWith("__Z")) continue
            attempted++
            if (applyDemangling(ctx.program, sym.address, name, monitor = ctx.monitor)) demangled++
        }
        log("demangle-attempted", count = attempted.toLong())
        log("demangle-applied", count = demangled.toLong())
    }

    /**
     * Force-create a function the stab asserts but Ghidra's auto-analysis missed (typical
     * for ctors only called from data-driven init lists, or vtable-only references).
     * Returns null if the address is in data or disassembly fails.
     */
    private fun tryCreateFunctionFromStab(open: OpenFunction): Function? {
        val addr = open.addr.address
        val block = ctx.program.memory.getBlock(addr)
        if (block == null || !block.isExecute) {
            // Inline std::/__gnu_cxx members get stabbed but the linker drops the COMDAT.
            // Bucket separately so real non-text-address problems aren't drowned out.
            val inlined = isInlineStdMember(open.name)
            val tag = if (inlined) "function-create-inlined-std" else "function-create-skipped-non-text"
            val level = if (inlined) Level.DEBUG else Level.WARN
            log(tag, "no executable block at $addr for ${open.name} (block=${block?.name})", level)
            return null
        }

        // CreateFunctionCmd refuses uninitialised code. MinGW COMDAT chunks that
        // autoanalysis hasn't reached need a manual disassemble first.
        if (ctx.program.listing.getInstructionAt(addr) == null) {
            val disasm = ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true)
            if (disasm.applyTo(ctx.program, ctx.monitor) && disasm.disassembledAddressSet.numAddresses > 0) {
                log("function-create-disassembled-first")
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
        log("function-created-from-stab")
        return ctx.program.functionManager.getFunctionAt(addr)
    }

    private fun analyzeBssCoverage(harvest: Harvest) {
        val bssBlock = ctx.program.memory.getBlock(".bss") ?: return

        val harvestedAddrs = harvest.symbolsByCu.values.flatten().mapNotNull {
            val name = (it.body as? SymbolDecl.Global)?.name ?: return@mapNotNull null
            val addr = ctx.resolver.resolve(name)?.offset
            HarvestedAddr(name, addr)
        }

        // 4-byte sweep, coalescing contiguous no-coverage into one log entry per range
        // (a per-chunk log produces thousands of lines on typical .bss).
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
     * Map gcc dbx register number → Ghidra register name. Architecture-specific
     * (gcc/config/<arch>/<arch>.h `DBX_REGISTER_NUMBER`). i386: 0..7 = eax,ecx,edx,ebx,
     * esp,ebp,esi,edi. x86_64 (SysV+Win64 agree): 0..7 = rax,rdx,rcx,rbx,rsi,rdi,rbp,
     * rsp; 8..15 = r8..r15.
     */
    private fun dbxRegisterName(dbxNum: Int): String? {
        val table = when (ctx.program.defaultPointerSize) {
            4 -> X86_DBX_TO_REGISTER
            8 -> X86_64_DBX_TO_REGISTER
            else -> return null
        }
        return table.getOrNull(dbxNum)
    }

    /**
     * Bias from gcc's frame-pointer-relative stab offsets to Ghidra's stackpointer-at-entry
     * offsets. gcc's frame origin is the saved frame pointer, one pointer below the return
     * address; Ghidra's origin is the return address, and the calling convention places the
     * first stack parameter exactly one pointer above it. Those two "one pointer" gaps are the
     * same slot, so the bias is precisely where the convention starts stack params —
     * [VariableUtilities.getBaseStackParamOffset] — not a hardcoded constant. It is a property
     * of the convention, so any function fixes it program-wide; absent one, fall back to a
     * pointer (the saved frame-pointer slot).
     */
    private fun deriveStackFrameBias(harvest: Harvest): Int = harvest.openFunctions
        .asSequence()
        .mapNotNull { ctx.program.functionManager.getFunctionAt(it.addr.address) }
        .firstNotNullOfOrNull { VariableUtilities.getBaseStackParamOffset(it) }
        ?: ctx.program.defaultPointerSize

    private fun applyLocal(
        func: Function,
        loc: SymbolRecord,
        typeRegistry: TypeRegistry,
        source: SourceType,
        frameBias: Int,
    ) {
        val decl = loc.body
        val resolvedDt = when (decl) {
            is SymbolDecl.StackLocal -> typeRegistry.dataTypeFor(decl.type)
            is SymbolDecl.RegLocal -> typeRegistry.dataTypeFor(decl.type)
            else -> return
        }
        if (resolvedDt == null) {
            ctx.diagnostics.recordDegradation("local-untyped", "${func.name}.${decl.name}]")
        }
        typeRegistry.reasonFor(resolvedDt)?.let { reason ->
            ctx.diagnostics.recordDegradation(
                "local-typed-$reason",
                "${func.name}.${decl.name}",
                "type=${resolvedDt?.pathName}",
            )
        }
        val dt = resolvedDt ?: Undefined4DataType.dataType
        try {
            when (decl) {
                is SymbolDecl.StackLocal -> {
                    if (decl.name in func.parameters.map { it.name }) {
                        log("local-var-skipped-dup-param")
                        return
                    }
                    if (decl.name in func.localVariables.map { it.name }) {
                        log("local-var-skipped-dup-local")
                        return
                    }
                    // gcc's frame-pointer-relative offset → Ghidra's SP-at-entry offset via the
                    // convention-derived [frameBias] (NSA/ghidra#223, #5485).
                    val stackOffset = loc.rawValue.toInt() - frameBias
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    log("local-var-add-success")
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
                        log("reglocal-skipped-dup-param")
                        return
                    }
                    if (decl.name in func.localVariables.map { it.name }) {
                        log("reglocal-skipped-dup-local")
                        return
                    }
                    val lv = LocalVariableImpl(decl.name, 0, dt, reg, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    log("reglocal-add-success")
                }
            }
        } catch (e: Exception) {
            // local-var-error counter auto-bumps via BookmarkSink tag→counter contract
            log("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}")
        }
    }

    private fun applyScopeComments(func: Function, open: OpenFunction) {
        // For each LBRAC/RBRAC pair, plate-comment the LBRAC with the in-scope locals.
        val pairs = ScopePairs.compute(open.scopeBrackets, open.locals)
        for ((openOff, _, localsInScope) in pairs) {
            try {
                val addr = func.entryPoint.add(openOff)

                if (localsInScope.isEmpty()) {
                    log("empty-scope", "addr=$addr function=${func.name}", Level.DEBUG)
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
            log("global-skipped", "addr=${decl.name} dtKind=unknown reason=unresolved-symbol", Level.DEBUG)
            return false
        }
        ensureStabLabel(addr, decl.name)

        val dt = typeRegistry.dataTypeFor(decl.type) ?: run {
            log("global-skipped", "addr=$addr dtKind=unknown reason=no-resolved-type", Level.DEBUG)
            return false
        }
        typeRegistry.reasonFor(dt)?.let { reason ->
            ctx.diagnostics.recordDegradation(
                "global-typed-$reason",
                decl.name,
                "type=${dt.pathName}",
            )
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
        // CLEAR_ALL_CONFLICT_DATA evicts `undefined4` placeholders auto-analysis may
        // have raced us to apply.
        try {
            ghidra.program.model.data.DataUtilities.createData(
                ctx.program,
                addr,
                dt,
                dt.length,
                ghidra.program.model.data.DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
            // Verify the write stuck — auto-analyser races or data-equivalence collapse
            // can replace it; we'd otherwise silently claim success.
            val after = ctx.program.listing.getDataAt(addr)
            val stuck = after != null && after.dataType.name == dt.name
            if (!stuck) {
                log(
                    "global-applied-then-overwritten",
                    "$decl.name at $addr: wrote ${dt.name} but readback is ${after?.dataType?.name}",
                )
            }
            log("global-applied", "addr=$addr dtKind=$dtKind", Level.DEBUG)
        } catch (e: Exception) {
            log("apply-error", "Failed to create global data at $addr: ${e.message}")
            log("global-skipped", "addr=$addr dtKind=$dtKind reason=create-data-failed", Level.DEBUG)
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
        typeRegistry.reasonFor(dt)?.let { reason ->
            ctx.diagnostics.recordDegradation(
                "static-typed-$reason",
                decl.name,
                "type=${dt.pathName}",
            )
        }
        ensureStabLabel(addr, decl.name)

        try {
            ctx.program.listing.clearCodeUnits(addr, addr.add((dt.length - 1).toLong()), false)
            ctx.program.listing.createData(addr, dt)
        } catch (e: Exception) {
            log("apply-error", "Failed to create static data at $addr: ${e.message}")
            return false
        }
        return true
    }

    /**
     * Make [name] (demangled source-form) the primary label at [addr]. Otherwise
     * globals/statics keep the PE loader's `_<name>` and the demangled form is never
     * in the symbol table. Idempotent.
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
