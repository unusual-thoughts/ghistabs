package ghistabs.importer

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.cmd.label.SetLabelPrimaryCmd
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.EnumDataType
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolTable
import ghistabs.Demangler
import ghistabs.baseStackParamOffset
import ghistabs.diagnose.ApplyErrorBucket
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.degradation
import ghistabs.forceCreateData
import ghistabs.harvest.*
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.itanium.Itanium.isInlineStdMember
import ghistabs.materialize.reasonFor
import ghistabs.materialize.resolveRef
import ghistabs.parse.*

/**
 * The apply phase: writes harvested functions, params, locals, globals, statics, labels and scope
 * comments into the Ghidra program, then demangles and materializes classes/vtables. Caller holds
 * the transaction.
 */
class SymbolApplier(
    private val ctx: ImportContext<*>,
    private val harvest: Harvest,
    private val registry: DataTypeRegistry,
) : DiagnosticSink by ctx {
    val source = SourceType.IMPORTED
    val symtab: SymbolTable get() = ctx.program.symbolTable
    val funMgr: FunctionManager get() = ctx.program.functionManager
    val pointerSize = ctx.program.defaultPointerSize

    /**
     * The N_PSYM list extended to the arity the mangled name declares. gcc emits no N_PSYM for an
     * *unnamed* parameter, so `void f(const NameValuePairs &)` leaves a stab list one short — and
     * applying a short list under DYNAMIC_STORAGE re-lays every slot: cryptopp's
     * `HMAC_Base::UncheckedSetKey(const byte*, unsigned int, const NameValuePairs&)` lost its third
     * argument, slid `userKey` into the `this` register, and decompiled to a body full of
     * `in_stack_` reads. The mangled name is the only place the true arity survives.
     *
     * Padding goes on the tail, where C++ puts unnamed parameters in practice; an unnamed one in the
     * middle would shift the names after it, but the storage — the part that breaks decompilation —
     * comes out right either way. `this` is not among the demangled parameters; ClassBuilder owns it.
     */
    private fun List<ParameterImpl>.padToMangledArity(mangled: String): List<ParameterImpl> {
        val declared = (Demangler.of(mangled) as? DemangledFunction)?.parameters
            ?.map { it.type }
            ?.filterNot { it.isVoid && it.pointerLevels == 0 && !it.isReference && !it.isArray }
            ?: return this
        if (declared.size <= size) return this
        degradation("param-unnamed-padded", mangled, "stabs=$size mangled=${declared.size}")
        return this +
            declared.drop(size).mapIndexed { i, t ->
                val dt = runCatching { t.getDataType(ctx.program.dataTypeManager) }.getOrNull()
                ParameterImpl("param_${size + i + 1}", dt ?: Undefined4DataType.dataType, ctx.program, source)
            }
    }

    internal fun applyAllFunctions(): Int {
        ctx.monitor.initialize(harvest.functions.size.toLong(), "Stabs: applying functions")
        var functions = 0

        for (open in harvest.functions) {
            ctx.monitor.increment()
            try {
                val func = funMgr.run {
                    getFunctionAt(open.addr) ?: getFunctionContaining(open.addr)?.also {
                        debug("entrypoint-snapped")
                    }
                } ?: tryCreateFunctionFromStab(open) ?: run {
                    val (tag, level) = if (isInlineStdMember(open.name)) {
                        "apply-error-inlined-std" to Level.DEBUG
                    } else {
                        "apply-error-no-function" to Level.INFO
                    }
                    // log() counts via the tee'd accumulator; BookmarkSink only emits/bookmarks.
                    log(tag, "no Function at or containing ${open.addr} for ${open.name}", level, open.addr)
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
                val retDt = registry.resolveRef(open.decl.type)

                // Build params from N_PSYM/N_RSYM. Filter out any N_PSYM literally named
                // `this`: gcc 3.x emits it for members but often mistypes (seen `int`
                // instead of `<Class>*`); ClassBuilder.reparentMethod sets __thiscall and
                // synthesises a typed `this` from the class struct, which is authoritative.
                // Keeping the N_PSYM one produces duplicate-`this` signatures Ghidra can't evict.
                val params = open.params
                    .filterNot {
                        it.body.name == "this"
                    }
                    .map { p ->
                        val pdt = registry.resolveRef(p.body.type)
                        if (pdt == null) {
                            degradation(
                                "param-untyped",
                                "${open.name}.${p.body.name}",
                            )
                        }
                        registry.reasonFor(pdt)?.let { reason ->
                            degradation(
                                "param-typed-$reason",
                                "${open.name}.${p.body.name}",
                                "type=${pdt?.pathName}",
                            )
                        }
                        ParameterImpl(
                            p.body.name,
                            pdt ?: Undefined4DataType.dataType,
                            ctx.program,
                            source,
                        )
                    }
                    .padToMangledArity(open.name)
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

                // Apply locals. Dedupe against the stabs parameter list, not a re-read of
                // func.parameters: in CONCURRENT mode another analyzer can mutate the function
                // between updateFunction above and this loop, which flipped locals between added
                // and skipped from run to run. This is `open.params`, before the `this` filter —
                // gcc also emits `this` as a register local at -O0, and that copy is redundant
                // once ClassBuilder has synthesised a typed one. A plain function whose own local
                // is called `this` has no such N_PSYM, so it keeps the local.
                val paramNames = open.params.mapTo(mutableSetOf()) { it.body.name }
                val firstUse = open.firstUseOffsets(func.entryPoint)
                for (loc in open.locals) {
                    applyLocal(func, loc, paramNames, firstUse[loc.recordIndex] ?: 0)
                }

                // Apply scope plate comments.
                if (ctx.options.applyPlateComments) applyScopeComments(func, open)

                functions++
            } catch (t: Throwable) {
                val bucket = ApplyErrorBucket.bucket(t)
                err("apply-error-$bucket", "function ${open.name}: ${t.message}", address = open.addr)
                err("apply-error", "function ${open.name}: ${t.message}", address = open.addr)
            }
        }
        return functions
    }

    internal fun applyAllGlobals(): Int {
        ctx.monitor.initialize(harvest.staticsByCu.values.sumOf { it.size }.toLong(), "Stabs: applying globals")
        var globals = 0

        // Globals + file-statics.
        for ((cu, syms) in harvest.staticsByCu) {
            for (sym in syms) {
                ctx.monitor.increment()
                try {
                    if (applyStatic(sym)) globals++
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

        for ((name, type, value) in harvest.constants) {
            // demangledName() is the unqualified leaf; rebuild the qualified name from the
            // namespace chain so the equate reads `CryptoPP::INFINITE_TIME`, not `INFINITE_TIME`.
            val ns = Demangler.namespaces(name).orEmpty()
            val leaf = Demangler.of(name)?.name ?: name
            val qualified = (ns + leaf).joinToString("::")

            when (val existing = equates.getEquate(qualified)) {
                null -> runCatching { equates.createEquate(qualified, value) }.onSuccess { applied++ }

                else -> if (existing.value != value) {
                    warn("constant-equate-conflict", "$qualified = ${existing.value} vs $value")
                }
            }
            enums.getOrPut(ns to (type.sizeBytes?.toInt() ?: byteSize(value))) {
                LinkedHashMap()
            }.putIfAbsent(leaf, value)
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
    private fun tryCreateFunctionFromStab(open: Func): Function? {
        val addr = open.addr
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
     * The name to give a local, or null when it is not a variable of its own. gcc names every inline
     * expansion's locals identically (`this` six times over in one function) and Ghidra's variable
     * namespace is flat, so distinct copies get `this`, `this_1`, … — but a same-named variable
     * already sitting in [isSameSlot] is gcc re-describing one variable, and suffixing that would
     * manufacture a twin.
     */
    private fun scopedName(func: Function, base: String, isSameSlot: (Variable) -> Boolean): String? {
        val sameBase = Regex("${Regex.escape(base)}(_\\d+)?")
        val existing = func.localVariables
        if (existing.any { sameBase.matches(it.name) && isSameSlot(it) }) return null
        val taken = existing.mapTo(mutableSetOf()) { it.name }
        return if (base !in taken) base else generateSequence(1, Int::inc).map { "${base}_$it" }.first { it !in taken }
    }

    private fun applyLocal(func: Function, loc: LocalSymbol, paramNames: Set<String>, firstUse: Int) {
        val decl = loc.body
        val dt = registry.resolveRef(decl.type)?.also {
            registry.reasonFor(it)?.let { reason ->
                degradation(
                    "local-typed-$reason",
                    "${func.name}.${decl.name}",
                    "type=${it.pathName}",
                )
            }
        } ?: run {
            degradation("local-untyped", "${func.name}.${decl.name}]")
            Undefined4DataType.dataType
        }

        try {
            when (decl.location) {
                VariableLocation.STACK -> {
                    if (decl.name in paramNames) {
                        debug("local-var-skipped-dup-param")
                        return
                    }
                    // Stack locals keep the drop-on-collision rule. They can't carry a scope — Ghidra
                    // rejects a non-zero firstUseOffset on stack storage ("Stack-based variable must
                    // have firstUseOffset of 0") — and suffixing them by slot instead is destructive:
                    // the extra copies land at offsets inside a real variable's footprint and Ghidra
                    // silently evicts it (one fixture's `main` lost a whole struct local outright).
                    if (decl.name in func.localVariables.map { it.name }) {
                        debug("local-var-skipped-dup-local")
                        return
                    }
                    // gcc's frame-pointer-relative offset → Ghidra's SP-at-entry offset via the
                    // convention-derived [frameBias] (NSA/ghidra#223, #5485).
                    val stackOffset = loc.rawValue.toInt() - ctx.program.baseStackParamOffset
                    val lv = LocalVariableImpl(decl.name, dt, stackOffset, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    debug("local-var-add-success")
                }

                VariableLocation.REGISTER -> {
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
                    if (decl.name in paramNames) {
                        debug("reglocal-skipped-dup-param")
                        return
                    }
                    val name = scopedName(func, decl.name) {
                        it.firstUseOffset == firstUse && it.register == reg
                    } ?: run {
                        debug("reglocal-skipped-dup-local")
                        return
                    }
                    // [firstUse] is the local's block, i.e. the range it is actually live over — a
                    // register local declared from entry claims the register for the whole function.
                    val lv = LocalVariableImpl(name, firstUse, dt, reg, ctx.program, source)
                    func.addLocalVariable(lv, source)
                    debug("reglocal-add-success", "firstUse=$firstUse")
                    if (name != decl.name) debug("reglocal-renamed-scope", "${decl.name} → $name")
                }
            }
        } catch (e: Exception) {
            warn("local-var-error", "Could not add local '${decl.name}' to ${func.name}: ${e.message}", func.entryPoint)
        }
    }

    private fun applyScopeComments(func: Function, open: Func) {
        fun comment(blocks: List<BlockScope>) {
            for ((start, _, locals, children) in blocks) {
                try {
                    if (locals.isEmpty()) {
                        debug("empty-scope", "function=${func.name}", address = start)
                    } else {
                        ctx.program.listing.setComment(start, CommentType.PLATE, scopeCommentText(locals))
                    }
                } catch (e: Exception) {
                    warn("scope-comment-error", "Failed to set scope comment: ${e.message}", func.entryPoint)
                }
                comment(children)
            }
        }
        comment(open.blocks)
    }

    /**
     * One `type name  storage  [header:line]` line per local, frame order first (deepest slot up),
     * registers after. gcc emits a fresh copy of an inlinee's locals at every inline expansion, each
     * in its own block, and a stack slot it reuses across disjoint scopes holds only one Ghidra
     * variable — Ghidra's frame maps an offset to at most one — so for everything shadowed there,
     * this comment is the only surviving record of the name, type and slot.
     */
    private fun scopeCommentText(locals: List<LocalSymbol>): String {
        val (stack, registers) = locals.partition { it.body.location == VariableLocation.STACK }
        val rows = (stack.sortedBy { it.rawValue } + registers.sortedBy { it.body.name }).map { loc ->
            val type = registry.resolveRef(loc.body.type)?.displayName ?: "?"
            val origin = loc.line ?.let { "[${loc.sourceFile.filename}:$it]" } ?: "[${loc.sourceFile.filename}]"
            Triple("$type ${loc.body.name}", loc.storage(ctx.program).orEmpty(), origin)
        }
        val declWidth = rows.maxOf { it.first.length }
        val storageWidth = rows.maxOf { it.second.length }
        return rows.joinToString("\n", "Stabs scope locals:\n") { (decl, storage, origin) ->
            "  ${decl.padEnd(declWidth)}  ${storage.padEnd(storageWidth)}  $origin".trimEnd()
        }
    }

    private fun applyStatic(sym: StaticSymbol): Boolean {
        val decl = sym.body
        val addr = ctx.resolver.forSymbol(sym) ?: run {
            warn("unresolved-symbol", "static ${decl.name}")
            debug("static-skipped", "addr=${decl.name} reason=unresolved-symbol")
            return false
        }

        ensureStabLabel(addr, sym.body.name)

        val dt = registry.resolveRef(decl.type) ?: run {
            warn("static-skipped", "reason=unresolved-ref", addr)
            return false
        }
        registry.reasonFor(dt)?.let { reason ->
            degradation(
                "global-typed-$reason",
                sym.body.name,
                "type=${dt.pathName}",
            )
        }

        if (ctx.options.applyPlateComments &&
            decl.scope == StaticScope.FUNCTION &&
            sym.enclosingFunction != null
        ) {
            ctx.program.listing.setComment(
                addr,
                CommentType.PLATE,
                "static local of ${Demangler.name(sym.enclosingFunction)}()",
            )
            debug("static-local-plate", address = addr)
        }

        try {
            // Cygwin PE with no .rdata section puts const data in .text, where it gets disassembled.
            val placed = ctx.program
                .forceCreateData(addr, dt) { debug("code-cleared-for-data", decl.name, address = addr) }

            // createData returns the data *covering* addr, which under CLEAR_ALL_CONFLICT_DATA can be
            // a larger item that already holds this type — isExistingNonDynamicType returns it as a
            // success without placing anything here. Compare where it actually starts.
            if (placed.minAddress != addr) {
                warn(
                    "global-offcut-in-larger-data",
                    "${decl.name} at $addr: ${dt.name} lands inside " +
                        "${placed.dataType.name}@${placed.minAddress}",
                    addr,
                )
            } else {
                ctx.program.sweepPointees(placed)
                    .takeIf { it > 0 }?.let { debug("pointee-typed", address = addr, count = it.toLong()) }
            }
            debug("global-applied", "dt=${dt.displayName}", address = addr)
        } catch (e: Exception) {
            err("apply-error", "global ${decl.name} at $addr: ${e.message}", addr)
            return false
        }
        return true
    }

    /**
     * Apply C++ static data members (`alnum:/2(5,44):_ZNSt10ctype_base5alnumE;`). They carry no
     * `G`/`S` address stab, so [applyStatic] never sees them and this linkage name is their
     * only link to the emitted symbol. Symbol-table-bound: a stripped binary resolves none.
     */
    internal fun applyAllStaticMembers(): Int {
        // One class is re-declared per including CU, so the same member arrives N times.
        val seen = mutableSetOf<String>()
        var applied = 0
        for (ast in registry.index.allTypes) {
            val body = ast.body as? TypeDecl.Struct<GlobalTypeId> ?: continue
            for (field in body.fields) {
                val mangled = field.mangled ?: continue
                if (!field.isStatic || !seen.add(mangled)) continue
                val addr = ctx.resolver.resolve(mangled) ?: run {
                    debug("static-member-unresolved", mangled)
                    continue
                }
                val dt = registry.resolveRef(field.type) ?: run {
                    degradation("static-member-untyped", mangled)
                    continue
                }
                // Names it `Class::member` when the demangler hasn't already; typed below regardless.
                ensureStabLabel(addr, mangled)
                try {
                    ctx.program.forceCreateData(addr, dt) { debug("code-cleared-for-data", mangled, address = addr) }
                    applied++
                    debug("static-member-applied", "$mangled dt=${dt.displayName}", address = addr)
                } catch (e: Exception) {
                    err("apply-error", "static member $mangled at $addr: ${e.message}", addr)
                }
            }
        }
        return applied
    }

    /**
     * Make [name] (demangled source-form) the primary label at [addr]. Otherwise,
     * globals/statics keep the PE loader's `_<name>` and the demangled form is never
     * in the symbol table. Idempotent.
     */
    private fun ensureStabLabel(addr: Address, name: String) {
        // Compiler-generated globals (typeinfo, typeinfo-name) carry their mangled `_ZTI…`/`_ZTS…`
        // linkage name in the stab. If the demangled label (`EAsm::typeinfo`) is already at this
        // address, leave it primary rather than promoting the raw mangled string over it.
        val demangledSimple = Demangler.of(name)?.name
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
