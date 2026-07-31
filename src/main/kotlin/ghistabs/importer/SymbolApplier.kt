package ghistabs.importer

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.cmd.label.SetLabelPrimaryCmd
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolTable
import ghistabs.demangle
import ghistabs.demangledName
import ghistabs.diagnose.ApplyErrorBucket
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.degradation
import ghistabs.harvest.Harvest
import ghistabs.harvest.OpenFunction
import ghistabs.harvest.SymbolRecord
import ghistabs.materialize.TypeRegistry
import ghistabs.materialize.reasonFor
import ghistabs.materialize.resolveRef
import ghistabs.namespaceChain
import ghistabs.parse.SymbolDecl
import ghistabs.parse.dbxRegisterName
import ghistabs.parse.isInlineStdMember

/**
 * The apply phase: writes harvested functions, params, locals, globals, statics, labels and scope
 * comments into the Ghidra program, then demangles and materializes classes/vtables. Caller holds
 * the transaction.
 */
class SymbolApplier(
    private val ctx: ImportContext<*>,
    private val harvest: Harvest,
    private val typeRegistry: TypeRegistry,
) : DiagnosticSink by ctx {
    val source = SourceType.IMPORTED
    val symtab: SymbolTable get() = ctx.program.symbolTable
    val funMgr: FunctionManager get() = ctx.program.functionManager
    val pointerSize = ctx.program.defaultPointerSize

    internal fun applyAllFunctions(): Int {
        ctx.monitor.initialize(harvest.openFunctions.size.toLong(), "Stabs: applying functions")
        var functions = 0

        for (open in harvest.openFunctions) {
            ctx.monitor.increment()
            try {
                val func = funMgr.run {
                    getFunctionAt(open.addr.address)
                        ?: getFunctionContaining(open.addr.address)?.also {
                            debug("entrypoint-snapped")
                        }
                } ?: tryCreateFunctionFromStab(open) ?: run {
                    val (tag, level) = if (isInlineStdMember(open.name)) {
                        "apply-error-inlined-std" to Level.DEBUG
                    } else {
                        "apply-error-no-function" to Level.INFO
                    }
                    // log() counts via the tee'd accumulator; BookmarkSink only emits/bookmarks.
                    log(tag, "no Function at or containing ${open.addr} for ${open.name}", level, open.addr.address)
                    continue
                }

                // The stabs are the authoritative, underscore-free source, so name every function
                // from them rather than riding Ghidra's PE symbol (which leaves C names as `_main`
                // and depends on the COFF symtab being present). Mangled names (`_ZN…`) are set raw
                // here and resolved to `Class::method` by demangleMangledLabels below — the raw name
                // is also load-bearing as ClassBuilder's method-address index, which on a stripped
                // binary has no other symbol to look up (see DemanglerReplacer.dropDisplacedMangledLabels).
                if (func.name != open.name) {
                    // COMDAT-folded placement `operator new`/`delete` put `open.name` on a *separate*
                    // symbol at this shared address, so renaming the function symbol throws "already
                    // exists at this address" — once per referencing CU, the bulk of
                    // `apply-error-duplicate-name`. Drop those redundant same-name symbols first; the
                    // function then adopts the name (correct output, no error).
                    symtab.getSymbols(func.entryPoint)
                        .filter { it != func.symbol && it.name == open.name }
                        .forEach { it.delete() }
                    func.setName(open.name, source)
                }

                // Resolve return type from the parsed signature; applied with the params below.
                val retDt = typeRegistry.resolveRef(open.decl.type)

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
                            is SymbolDecl.StackParam -> pdecl.name to typeRegistry.resolveRef(pdecl.type)
                            is SymbolDecl.RegParam -> pdecl.name to typeRegistry.resolveRef(pdecl.type)
                            else -> "arg$i" to null
                        }
                        if (pdt == null) {
                            degradation(
                                "param-untyped",
                                "${open.name}.$pname",
                            )
                        }
                        typeRegistry.reasonFor(pdt)?.let { reason ->
                            degradation(
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
                // Set return + params in one dynamic-storage update so Ghidra recomputes storage from
                // the calling convention. Critical for by-value struct returns >8 bytes (hidden return
                // pointer): setReturnType alone keeps the 4-byte EAX register slot and throws "Storage
                // can't be expanded to N bytes: EAX:4".
                func.updateFunction(
                    null,
                    retDt?.let { ReturnParameterImpl(it, ctx.program) } ?: func.getReturn(),
                    params,
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    true,
                    source,
                )

                // Apply locals.
                for (loc in open.locals) {
                    applyLocal(func, loc)
                }

                // Apply scope plate comments.
                if (ctx.options.applyPlateComments) applyScopeComments(func, open)

                functions++
            } catch (t: Throwable) {
                val bucket = ApplyErrorBucket.bucket(t)
                err("apply-error-$bucket", "function ${open.name}: ${t.message}", address = open.addr.address)
                err("apply-error", "function ${open.name}: ${t.message}", address = open.addr.address)
            }
        }
        return functions
    }

    internal fun applyAllGlobals(): Int {
        ctx.monitor.initialize(harvest.symbolsByCu.values.sumOf { it.size }.toLong(), "Stabs: applying globals")
        var globals = 0

        // Globals + file-statics.
        for ((cu, syms) in harvest.symbolsByCu) {
            for (sym in syms) {
                ctx.monitor.increment()
                try {
                    if (applyGlobalOrStatic(sym)) globals++
                } catch (t: Throwable) {
                    err("apply-error", "symbol ${sym.body.name} in $cu: ${t.message}")
                }
            }
        }

        return globals
    }

    /**
     * Apply addressless `:c` constants. They have no use-site, so instead of a data definition
     * we give them two synthetic homes: an equate per constant (value↔name, applicable wherever
     * the scalar shows up) and a browsable per-(namespace, byte-size) enum catalog under
     * `/stabs/constants`. Grouping by size keeps each enum's width honest — no 8-byte grab-bag.
     * The catalog enum is explicitly synthetic; real enums only ever come from `TypeDecl.Enum`.
     */
    internal fun applyAllConstants(): Int {
        if (harvest.constants.isEmpty()) return 0
        val equates = ctx.program.equateTable
        // (namespace-chain, byte-size) → leaf-name → value
        val enums = LinkedHashMap<Pair<List<String>, Int>, LinkedHashMap<String, Long>>()
        var applied = 0

        for (c in harvest.constants) {
            // demangledName() is the unqualified leaf; rebuild the qualified name from the
            // namespace chain so the equate reads `CryptoPP::INFINITE_TIME`, not `INFINITE_TIME`.
            val ns = namespaceChain(c.name).orEmpty()
            val leaf = demangle(c.name)?.name ?: c.name
            val qualified = (ns + leaf).joinToString("::")

            when (val existing = equates.getEquate(qualified)) {
                null -> runCatching { equates.createEquate(qualified, c.value) }.onSuccess { applied++ }

                else -> if (existing.value != c.value) {
                    warn("constant-equate-conflict", "$qualified = ${existing.value} vs ${c.value}")
                }
            }
            enums.getOrPut(ns to byteSize(c.value)) { LinkedHashMap() }.putIfAbsent(leaf, c.value)
        }

        val dtm = ctx.program.dataTypeManager
        for ((key, members) in enums) {
            val (ns, size) = key
            val category = ns.fold(CategoryPath("/stabs/constants")) { path, seg -> CategoryPath(path, seg) }
            val enum = EnumDataType(category, "size_${size}b", size, dtm)
            members.forEach { (n, v) -> enum.add(n, v) }
            dtm.addDataType(enum, DataTypeConflictHandler.REPLACE_HANDLER)
        }

        debug("apply-constants", count = applied.toLong())
        debug("apply-constant-enums", count = enums.size.toLong())
        return applied
    }

    /** Minimal enum width (1/2/4/8 bytes) that holds [v] in either signed or unsigned range. */
    private fun byteSize(v: Long) = when (v) {
        in -0x80L..0xFFL -> 1
        in -0x8000L..0xFFFFL -> 2
        in -0x8000_0000L..0xFFFF_FFFFL -> 4
        else -> 8
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
            val (tag, level) = if (inlined) {
                "function-create-inlined-std" to Level.DEBUG
            } else {
                "function-create-skipped-non-text" to Level.WARN
            }
            log(tag, "no executable block at $addr for ${open.name} (block=${block?.name})", level, addr)
            return null
        }

        // CreateFunctionCmd refuses uninitialised code. MinGW COMDAT chunks that
        // autoanalysis hasn't reached need a manual disassemble first.
        if (ctx.program.listing.getInstructionAt(addr) == null) {
            val disasm = DisassembleCommand(addr, null, true)
            if (disasm.applyTo(ctx.program, ctx.monitor) && disasm.disassembledAddressSet.numAddresses > 0) {
                debug("function-create-disassembled-first")
            } else {
                warn(
                    "function-create-disasm-failed",
                    "DisassembleCommand failed at $addr for ${open.name}: ${disasm.statusMsg}",
                    addr,
                )
                return null
            }
        }

        val cmd = CreateFunctionCmd(open.name, addr, null, SourceType.IMPORTED)
        if (!cmd.applyTo(ctx.program, ctx.monitor)) {
            warn(
                "function-create-cmd-failed",
                "CreateFunctionCmd failed at $addr for ${open.name}: ${cmd.statusMsg}",
                addr,
            )
            return null
        }
        debug("function-created-from-stab")
        return funMgr.getFunctionAt(addr)
    }

    /**
     * Bias from gcc's frame-pointer-relative stab offsets to Ghidra's stackpointer-at-entry offsets.
     * gcc's frame origin is the saved frame pointer, one pointer below the return address; Ghidra's
     * origin is the return address, and the convention places the first stack parameter exactly one
     * pointer above it. Those two "one pointer" gaps are the same slot, so the bias is precisely
     * where the convention starts stack params — [VariableUtilities.getBaseStackParamOffset] — not a
     * hardcoded constant. Any function fixes it program-wide; absent one, fall back to a pointer.
     */
    private val frameBias by lazy {
        harvest.openFunctions
            .asSequence()
            .mapNotNull { funMgr.getFunctionAt(it.addr.address) }
            .firstNotNullOfOrNull { VariableUtilities.getBaseStackParamOffset(it) }
            ?: pointerSize
    }

    private fun applyLocal(func: Function, loc: SymbolRecord) {
        val decl = loc.body
        val resolvedDt = when (decl) {
            is SymbolDecl.StackLocal -> typeRegistry.resolveRef(decl.type)
            is SymbolDecl.RegLocal -> typeRegistry.resolveRef(decl.type)
            else -> return
        }
        if (resolvedDt == null) {
            degradation("local-untyped", "${func.name}.${decl.name}]")
        }
        typeRegistry.reasonFor(resolvedDt)?.let { reason ->
            degradation(
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
                        debug("local-var-skipped-dup-param")
                        return
                    }
                    if (decl.name in func.localVariables.map { it.name }) {
                        debug("local-var-skipped-dup-local")
                        return
                    }
                    // gcc's frame-pointer-relative offset → Ghidra's SP-at-entry offset via the
                    // convention-derived [frameBias] (NSA/ghidra#223, #5485).
                    val stackOffset = loc.rawValue.toInt() - frameBias
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    debug("local-var-add-success")
                }

                is SymbolDecl.RegLocal -> {
                    // The dbx register number is the stab's n_value, not part of the descriptor
                    // (`w:r(0,5)` ends at the type) — same field the stack offset above comes from.
                    val dbxNum = loc.rawValue.toInt()
                    val regName = dbxRegisterName(pointerSize, dbxNum)
                    val reg = regName?.let { ctx.program.getRegister(it) }
                    if (reg == null) {
                        degradation(
                            "reglocal-unmapped-regnum",
                            "${func.name}.${decl.name}",
                            "dbx-reg=$dbxNum arch-ptr-size=$pointerSize",
                        )
                        return
                    }
                    if (decl.name in func.parameters.map { it.name }) {
                        debug("reglocal-skipped-dup-param")
                        return
                    }
                    if (decl.name in func.localVariables.map { it.name }) {
                        debug("reglocal-skipped-dup-local")
                        return
                    }
                    val lv = LocalVariableImpl(decl.name, 0, dt, reg, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    debug("reglocal-add-success")
                }
            }
        } catch (e: Exception) {
            warn("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}", func.entryPoint)
        }
    }

    private fun applyScopeComments(func: Function, open: OpenFunction) {
        // For each LBRAC/RBRAC pair, plate-comment the LBRAC with the in-scope locals.
        val pairs = ScopePairs.compute(open.scopeBrackets, open.locals)
        for ((openOff, _, localsInScope) in pairs) {
            try {
                val addr = func.entryPoint.add(openOff)

                if (localsInScope.isEmpty()) {
                    debug("empty-scope", "addr=$addr function=${func.name}")
                    continue
                }
                val text = "Stabs scope locals: " + localsInScope.joinToString(", ") { it.body.name }
                ctx.program.listing.setComment(addr, CommentType.PLATE, text)
            } catch (e: Exception) {
                warn("scope-comment-error", "Failed to set scope comment: ${e.message}", func.entryPoint)
            }
        }
    }

    private fun applyGlobalOrStatic(sym: SymbolRecord): Boolean {
        val addr = when (val decl = sym.body) {
            is SymbolDecl.StaticVar -> ctx.resolver.buildAddress(sym.rawValue)

            is SymbolDecl.Global -> ctx.resolver.resolve(decl.name) ?: run {
                warn("unresolved-symbol", "global ${decl.name}")
                debug("global-skipped", "addr=${decl.name} reason=unresolved-symbol")
                return false
            }

            else -> {
                warn("unexpected-symbol", "$decl")
                return false
            }
        }
        ensureStabLabel(addr, sym.body.name)

        val dt = typeRegistry.resolveRef(sym.body.type) ?: return false
        typeRegistry.reasonFor(dt)?.let { reason ->
            degradation(
                "global-typed-$reason",
                sym.body.name,
                "type=${dt.pathName}",
            )
        }

        if (ctx.options.applyPlateComments &&
            (sym.body as? SymbolDecl.StaticVar)?.isFunctionLocal == true &&
            sym.enclosingFunction != null
        ) {
            ctx.program.listing.setComment(
                addr,
                CommentType.PLATE,
                "static local of ${demangledName(sym.enclosingFunction)}()",
            )
            debug("static-local-plate", address = addr)
        }

        // CLEAR_ALL_CONFLICT_DATA evicts `undefined4` placeholders auto-analysis may have raced us to apply.
        try {
            DataUtilities.createData(
                ctx.program,
                addr,
                dt,
                dt.length,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )

            // Confirm createData actually placed dt. On some stab addresses nothing lands (getDataAt
            // null — unmapped/uninitialised target or a silent conflict; cause unconfirmed, see
            // pending-work-triage.md). Synchronous inside our transaction, so this reflects createData's
            // own result, not a later auto-analysis overwrite. isEquivalent (not identity) so the
            // DTM-resolved copy of dt isn't a false mismatch.
            val after = ctx.program.listing.getDataAt(addr)
            if (after?.dataType?.isEquivalent(dt) != true) {
                warn(
                    "global-applied-then-overwritten",
                    "${sym.body.name} at $addr: wrote ${dt.name} but readback is ${after?.dataType?.name}",
                    addr,
                )
            }
            after?.let { ctx.program.sweepPointees(it) }
                .takeIf { (it ?: 0) > 0 }?.let { debug("pointee-typed", address = addr, count = it.toLong()) }
            debug("global-applied", "dt=${dt.displayName}", address = addr)
        } catch (e: Exception) {
            err("apply-error", "Failed to create global data at $addr: ${e.message}", addr)
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
        // Compiler-generated globals (typeinfo, typeinfo-name) carry their mangled `_ZTI…`/`_ZTS…`
        // linkage name in the stab. If the demangled label (`EAsm::typeinfo`) is already at this
        // address, leave it primary rather than promoting the raw mangled string over it.
        val demangledSimple = demangle(name)?.name
        if (demangledSimple != null && symtab.getSymbols(addr).any { it.name == demangledSimple }) return

        val existing = symtab.getSymbols(addr).firstOrNull { it.name == name }
        val sym = existing ?: try {
            symtab.createLabel(addr, name, SourceType.IMPORTED)
        } catch (e: Exception) {
            err("symbol-create-error", "$name at $addr: ${e.message}", addr)
            return
        }
        if (!sym.isPrimary) {
            try {
                SetLabelPrimaryCmd(addr, sym.name, sym.parentNamespace).applyTo(ctx.program)
            } catch (e: Exception) {
                err("symbol-primary-error", "$name at $addr: ${e.message}", addr)
            }
        }
    }
}
