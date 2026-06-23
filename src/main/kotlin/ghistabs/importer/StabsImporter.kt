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
import ghistabs.harvest.Harvest
import ghistabs.harvest.Harvester
import ghistabs.harvest.LocalRecord
import ghistabs.harvest.OpenFunction
import ghistabs.harvest.TypeResolver
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
        // Resolver wraps the harvest with by-name/by-base-tag indices, oracle
        // duties, canonicalization, and divergent-collision filtering. Everything
        // downstream that needs cross-CU lookups talks to this.
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

        // Report placeholders that never had their bodies resolved. These are
        // empty StructureDataTypes left in the DTM at end-of-import; downstream
        // they'd cause "Offset 0 beyond end of structure" merge errors and bogus
        // type info in the listing. Logging them named makes the cause findable
        // instead of just showing up as cascading errors elsewhere.
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
        ctx.diagnostics.inc("harvest-globals", allSyms.count { it.decl is SymbolDecl.Global }.toLong())
        ctx.diagnostics.inc("harvest-statics", allSyms.count { it.decl is SymbolDecl.StaticVar }.toLong())
        ctx.diagnostics.inc("harvest-typeAsts", harvest.typeAsts.size.toLong())
        // typeAst breakdown by AST kind — surfaces struct/enum/typedef weights.
        val byKind = harvest.typeAsts.values.groupingBy { it.body::class.simpleName ?: "Unknown" }.eachCount()
        for ((kind, n) in byKind.toSortedMap()) {
            ctx.diagnostics.inc("harvest-typeAsts-$kind", n.toLong())
        }
        // Per-CU count of harvested symbols — top contributors land in the
        // examples bucket so a single huge CU is visible.
        ctx.diagnostics.inc("harvest-cus", harvest.symbolsByCu.size.toLong())
        // Names dropped during harvest (parse error or canonicalisation
        // collision) versus what reached PassA's output.
        val uniqueTypeIds = harvest.typeAsts.keys.size
        ctx.diagnostics.inc("harvest-typeAsts-unique-by-id", uniqueTypeIds.toLong())
        ctx.diagnostics.inc("harvest-typeAsts-dup-by-id", (harvest.typeAsts.size - uniqueTypeIds).toLong())
        ctx.diagnostics.inc("harvest-collisions-raw", harvest.rawCollisions.size.toLong())
        ctx.diagnostics.inc(
            "harvest-collisions-raw-total",
            harvest.rawCollisions.values.flatMap { it.values }.flatten().count().toLong(),
        )
        // Post-filter: content-equivalent duplicates dropped, only genuinely
        // divergent multi-body collisions remain.
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
                log("apply-error-$bucket", "function ${open.name}: ${t.message}")
                log("apply-error", "function ${open.name}: ${t.message}", address = open.addr.address)
            }
        }

        // Globals + file-statics.
        for ((cu, syms) in harvest.symbolsByCu) {
            for (h in syms) {
                try {
                    when (val d = h.decl) {
                        is SymbolDecl.Global -> applyGlobal(d, typeRegistry).let { if (it) globals++ }

                        is SymbolDecl.StaticVar -> applyStatic(d, h.rawValue, typeRegistry).let {
                            if (it) globals++
                        }

                        else -> log("unexpected-symbol", "$d")
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
            val classBuilder = ghistabs.materialize.ClassBuilder(typeRegistry, harvest, typeResolver, ctx)
            // Each class header transitively included by N CUs produces N TypeAst
            // entries with distinct GlobalTypeIds but identical `ghidraName`
            // (xapasmcsr: 86 names duplicated, up to 11x each). `materialiseAll`
            // already collapsed them into one DTM Structure per name; group here
            // so we build each class once, with two extra requirements:
            //
            //  * Attribution gets the *union* of defining CUs, matching the key
            //    `materialiseAll` used when picking a category. Without this,
            //    most ASTs would resolve to a non-canonical category and the
            //    DTM lookup would miss (cf. old `[class-not-struct]` spam).
            //  * Among same-name ASTs, pick the most-detailed body (max methods,
            //    then max fields). Different transitive-include paths can see
            //    different completeness — e.g. one CU sees only the forward
            //    decl, another the full body with methods.
            ctx.diagnostics.inc(
                "class-build-name-collisions",
                harvest.typeAsts.values.groupingBy { it.ghidraName }.eachCount()
                    .values.count { it > 1 }.toLong(),
            )
            for (group in typeResolver.byCanonicalKey.values) {
                if (group.ast.body !is TypeDecl.Struct) {
                    continue
                }

                // ClassBuilder.build is the only path that builds <Class>_vtable
                // structs and assigns __thiscall. gcc 12 emits the vfptr as a
                // regular field `_vptr.XX` instead of the `~%<id>;` marker
                // hasVTablePointerMarker watches for, so the empty-methods +
                // no-marker check below would silently skip every polymorphic
                // class in xmltest. Treat a `_vptr*` field as the same signal.
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
        val block = ctx.program.memory.getBlock(addr)
        if (block == null || !block.isExecute) {
            // Inline std::/`__gnu_cxx`:: members emitted by gcc are routinely declared
            // in stabs but never make it into .text (the compiler inlined every call
            // site, the linker dropped the COMDAT). Log at DEBUG with a dedicated
            // counter so the noise doesn't drown out real "non-executable address"
            // problems on user code.
            val inlined = isInlineStdMember(open.name)
            val tag = if (inlined) "function-create-inlined-std" else "function-create-skipped-non-text"
            val level = if (inlined) Level.DEBUG else Level.WARN
            log(tag, "no executable block at $addr for ${open.name} (block=${block?.name})", level)
            return null
        }

        // CreateFunctionCmd refuses to start a function on uninitialised code.
        // For MinGW COMDAT chunks Ghidra's autoanalysis sometimes hasn't reached,
        // disassemble first so the cmd has an Instruction to anchor on.
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

    /**
     * Map gcc's dbx register number to a Ghidra register name. The mapping
     * is architecture-specific; gcc/config/<arch>/<arch>.h defines
     * `DBX_REGISTER_NUMBER` for each target. We cover the two relevant
     * cases for the test fixtures:
     *  - 32-bit x86 (i386 ABI, used by Cygwin/MinGW PE binaries):
     *    0..7 = eax,ecx,edx,ebx,esp,ebp,esi,edi.
     *  - x86_64 (SysV / Win64 — both agree on the dbx mapping):
     *    0..7 = rax,rdx,rcx,rbx,rsi,rdi,rbp,rsp, then 8..15 = r8..r15.
     * Returns null if the regNum or pointer size doesn't match a known
     * mapping; the caller logs a degradation rather than crashing.
     */
    private fun dbxRegisterName(dbxNum: Int): String? {
        val table = when (ctx.program.defaultPointerSize) {
            4 -> X86_DBX_TO_REGISTER
            8 -> X86_64_DBX_TO_REGISTER
            else -> return null
        }
        return table.getOrNull(dbxNum)
    }

    private fun applyLocal(func: Function, loc: LocalRecord, typeRegistry: TypeRegistry, source: SourceType) {
        val decl = loc.decl
        val resolvedDt = when (decl) {
            is SymbolDecl.StackLocal -> typeRegistry.dataTypeFor(decl.type)
            is SymbolDecl.RegLocal -> typeRegistry.dataTypeFor(decl.type)
            else -> return
        }
        if (resolvedDt == null) {
            val localName = when (decl) {
                is SymbolDecl.StackLocal -> decl.name
                is SymbolDecl.RegLocal -> decl.name
            }
            ctx.diagnostics.recordDegradation("local-untyped", "${func.name}.$localName")
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
     * Make `name` (the demangled C/C++ source-form name from the stab) the
     * primary label at `addr`. Without this, globals/statics keep the PE
     * loader's `_<name>` label and the demangled form never appears in the
     * symbol table.
     *
     * Idempotent: skips creation when a same-named symbol already exists, and
     * skips re-promotion when it's already primary.
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
