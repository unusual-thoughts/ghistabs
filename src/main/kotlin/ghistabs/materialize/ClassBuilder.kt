package ghistabs.materialize

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.NamespaceUtils
import ghidra.app.util.demangler.DemanglerOptions
import ghidra.app.util.demangler.DemanglerUtil
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.isInlineStdMember
import ghistabs.harvest.CanonicalGroup
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.parse.*

/**
 * Static helpers for polymorphic base detection (extracted for pure unit testing).
 */
internal class ClassBuilderHelpers(val resolver: TypeResolver) {
    fun hasPolymorphicBaseSubobject(body: TypeDecl.Struct<GlobalTypeId>) = firstPolymorphicBase(body) != null

    fun firstPolymorphicBase(body: TypeDecl.Struct<GlobalTypeId>): BaseDecl<GlobalTypeId>? = body.bases
        .sortedBy { it.offsetBits }
        .firstOrNull { base ->
            val baseStruct =
                resolveBaseAstStatic(base.type) ?: return@firstOrNull false
            baseStruct.hasVTablePointerMarker ||
                baseStruct.methods.any { it.virt == VirtKind.VIRTUAL } ||
                firstPolymorphicBase(baseStruct) != null
        }

    fun resolveBaseAstStatic(typeDecl: TypeDecl<GlobalTypeId>): TypeDecl.Struct<GlobalTypeId>? = when (typeDecl) {
        is TypeDecl.Ref -> resolver.getStruct(typeDecl.id)

        is TypeDecl.XRef -> resolver.byXRef(typeDecl)?.body as? TypeDecl.Struct<GlobalTypeId>

        // Inline definition: prefer the materialised AST at this id (real struct body), fall
        // back to the inline body. The inline body is often a forward XRef stub whose Struct
        // form lives at typeAstsById[typeDecl.id] — without this fallback, base polymorphism
        // detection misses inherited vfptrs (e.g. bouniaf → InlineDef(ExprInst id, XRef body)).
        is TypeDecl.InlineDef -> resolver.getStruct(typeDecl.id)
            ?: (typeDecl.body as? TypeDecl.Struct)
            ?: resolveBaseAstStatic(typeDecl.body)

        else -> null
    }
}

class ClassBuilder(
    private val typeRegistry: TypeRegistry,
    private val harvest: Harvest,
    private val typeResolver: TypeResolver,
    private val ctx: ImportContext<*>,
) : DiagnosticSink by ctx.sink {
    private val source = SourceType.IMPORTED
    private val program = ctx.program
    private val resolver = ctx.resolver
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

    /** Materialise a class struct + namespace + (optional) vtable struct + apply at _ZTV. */
    fun build(group: CanonicalGroup) {
        val name = group.key.name
        val category = group.key.category
        val body = group.ast.body as TypeDecl.Struct<GlobalTypeId>
        // 1. Look up the materialised Structure registered by materialiseAll for this group's
        //    winner — TypeRegistry is the authoritative source; no DTM round-trip needed.
        val structDt = typeRegistry.dataTypeFor(group.ast.id)
        if (structDt !is Structure) {
            log("class-not-struct", "skipping ${structDt?.let { it::class.simpleName }} class '$name' at $category ")
            return
        }

        // 2. Insert {vfptr} first if class is polymorphic.
        val isPoly = body.hasVTablePointerMarker ||
            body.methods.any { it.virt == VirtKind.VIRTUAL } ||
            body.fields.any {
                it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr"
            }
        if (isPoly) ensureVfptrFirstField(structDt, body, name, category)

        // 3. Create or upgrade the GhidraClass namespace.
        val ns = ensureClassNamespace(name, body)

        // 4. Re-parent member functions.
        for (m in body.methods) reparentMethod(m, name, ns, structDt)

        // 5. If polymorphic: build <Class>_vtable struct + apply at _ZTV<class> address.
        if (isPoly) buildAndApplyVtable(name, body, ns, category, structDt)
    }

    /**
     * Build (or upgrade) the GhidraClass for this struct.
     *
     * Two paths:
     *  1. If any method carries an Itanium mangled symbol, demangle it and
     *     walk `Demangled.getNamespace()` parent-chain to derive the class's
     *     fully-qualified namespace structure. Avoids any string splitting
     *     and inherits Ghidra's handling of templated names.
     *  2. Otherwise (struct with no methods, or unmangleable symbol), fall
     *     back to a depth-aware split of the demangled C++ source-form name
     *     so that `::` inside template args doesn't shred parameters.
     */
    private fun ensureClassNamespace(name: String, body: TypeDecl.Struct<GlobalTypeId>): GhidraClass {
        val parts = body.methods.firstNotNullOfOrNull { it.mangled }
            ?.let { namespaceChainFromMangled(it) }
            ?: QualifiedName.split(name)
        return buildNamespaceChain(parts.filter { it.isNotEmpty() })
    }

    /**
     * Demangle [mangled] and return the parent-namespace chain root-first
     * (so the leaf is the immediate-enclosing class). Returns null if the
     * symbol can't be demangled or has no namespace parent.
     */
    private fun namespaceChainFromMangled(mangled: String): List<String>? {
        val obj = try {
            DemanglerUtil.demangle(program, mangled, null).firstOrNull()
        } catch (_: Throwable) {
            null
        } ?: return null
        val parent = obj.namespace ?: return null
        return generateSequence(parent) { it.namespace }
            .map { it.name }
            .toList()
            .asReversed()
    }

    private fun buildNamespaceChain(parts: List<String>): GhidraClass {
        var parent: Namespace? = null
        for ((i, part) in parts.withIndex()) {
            val isLast = i == parts.lastIndex
            val existing = symtab.getNamespace(part, parent)
            parent = when (existing) {
                null if isLast -> symtab.createClass(parent, part, source)

                null -> symtab.createNameSpace(parent, part, source)

                else if (isLast && existing !is GhidraClass) ->
                    NamespaceUtils.convertNamespaceToClass(existing)

                else -> existing
            }
        }
        return parent as GhidraClass
    }

    private fun ensureVfptrFirstField(
        structDt: Structure,
        body: TypeDecl.Struct<GlobalTypeId>,
        className: String,
        category: CategoryPath,
    ) {
        val vfptrName = ClassUtils.VFPTR // "{vfptr}"

        // Collect parser-emitted _vptr field offset if present
        val parserVptrOffset = body.fields
            .firstOrNull {
                it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr"
            }?.let { (it.offsetBits / 8).toInt() }

        // Snapshot existing component at target offset
        val targetOffset = parserVptrOffset ?: 0
        val existingComp = runCatching { structDt.getComponentAt(targetOffset) }.getOrNull()
        val snapshot = existingComp?.let {
            FirstComponentSnapshot(
                fieldName = it.fieldName,
                offsetBytes = it.offset,
                isUndefined = it.dataType is Undefined1DataType,
            )
        }

        // Decide what to do with vfptr placement
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = hasPolymorphicBaseSubobject(body),
            parserVptrOffsetBytes = parserVptrOffset,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = vfptrName,
        )

        when (action) {
            is VfptrAction.SkipInheritedFromBase -> ctx.diagnostics.inc("vfptr-inherited-from-base")

            is VfptrAction.AlreadyCanonical -> return

            is VfptrAction.Insert -> {
                val ptrToVtable = ensureVtableTypeAndPointer(className, category)
                structDt.insertAtOffset(
                    action.offsetBytes,
                    ptrToVtable,
                    ptrToVtable.length,
                    vfptrName,
                    "vtable pointer",
                )
                ctx.diagnostics.inc("vfptr-inserted")
            }

            is VfptrAction.Replace -> {
                val ptrToVtable = ensureVtableTypeAndPointer(className, category)
                structDt.replaceAtOffset(
                    action.offsetBytes,
                    ptrToVtable,
                    ptrToVtable.length,
                    vfptrName,
                    "vtable pointer (was: ${action.wasFieldName})",
                )
                ctx.diagnostics.inc("vfptr-normalized")
            }

            is VfptrAction.CollisionAt -> log(
                "vfptr-collision",
                "$className: cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})",
            )
        }
    }

    /**
     * The {vfptr} field in a polymorphic object points at the FUNCTION POINTER ARRAY
     * inside the vtable record (i.e. `_ZTV<class> + 2*ptrSize`), not at the start of
     * the record. We model that by giving the function pointer array its own struct
     * `<Class>_vftable` and having {vfptr} be `<Class>_vftable*`. The full vtable
     * record `<Class>_vtable` (offset_to_top + rtti + embedded vftable) gets applied
     * at the `_ZTV` address.
     *
     * The vftable struct lives under `/ClassDataTypes/<Class>/` to match the
     * convention `RecoveredClassHelper.createVftableStructures` uses, so
     * `ApplyClassFunctionSignatureUpdatesScript` (shift-S round-trip) can find it.
     */
    private fun ensureVtableTypeAndPointer(
        className: String,
        @Suppress("UNUSED_PARAMETER") category: CategoryPath,
    ): Pointer {
        val vftableCategory = CategoryPath(CategoryPath(CategoryPath.ROOT, "ClassDataTypes"), className)
        val name = "${className}_vftable"
        val struct = typeRegistry.getOrRegister<DataType>(vftableCategory, name) {
            StructureDataType(vftableCategory, name, 0, dtm)
        }
        return PointerDataType.getPointer(struct, dtm)
    }

    private fun reparentMethod(m: MethodDecl<GlobalTypeId>, className: String, ns: GhidraClass, structDt: Structure) {
        val mangled = m.mangled ?: run {
            log("method-no-mangled", "$className::${m.name}: stab has no mangled symbol")
            return
        }
        val addr = resolver.resolve(mangled) ?: run {
            // Compiler-implicit trivial special members (default/copy/move ctor & dtor,
            // copy/move assignment) appear in every class's stab method list but the
            // compiler emits no symbol for them when they are trivial. These are not
            // real "unresolved" failures — bucket them separately so the unresolved
            // log surfaces actual problems.
            if (isLikelyImplicitTrivialSpecialMember(mangled)) {
                ctx.diagnostics.inc("method-implicit-not-emitted")
            } else {
                log("unresolved-symbol", "method $mangled (in $className)", Level.DEBUG)
            }
            return
        }
        val func = program.functionManager.getFunctionAt(addr) ?: run {
            val tag: String
            val level: Level
            if (isInlineStdMember(mangled)) {
                tag = "unresolved-symbol-inlined-std"
                level = Level.DEBUG
            } else {
                tag = "unresolved-symbol"
                level = Level.WARN
            }
            log(tag, "no Function at $addr for $mangled", level)
            return
        }

        // 1. Re-parent + rename via Ghidra's demangler. `ensureClassNamespace`
        //    already created the GhidraClass leaf, so
        //    `applyDemangledName.getOrCreateNameSpace` reuses it (and the
        //    method ends up in the right class with `thiscall`-friendly
        //    `parentNamespace is GhidraClass`). Disable signature/calling-
        //    convention/disassembly application — the stab gives us richer
        //    types than the demangler can derive from the mangled name, and
        //    our `__thiscall` choice below must win.
        val demangleOpts = DemanglerOptions().apply {
            setApplySignature(false)
            setApplyCallingConvention(false)
            setDoDisassembly(false)
        }
        val demangleCmd = DemanglerCmd(addr, mangled, demangleOpts)
        if (!demangleCmd.applyTo(program)) {
            // Demangler couldn't parse the symbol — fall back to manual
            // namespace + display-name handling so we still produce a
            // usable class layout.
            func.parentNamespace = ns
            val fallbackName = displayNameFor(mangled, className) ?: m.name
            if (func.name != fallbackName) func.setName(fallbackName, source)
            ctx.diagnostics.recordDegradation(
                "method-demangle-fallback",
                "$className::${m.name}",
                demangleCmd.statusMsg,
            )
        }

        // 3. Mark thiscall. Calling convention drives `this`:
        //    On x86 PE/Cygwin (`x86win32`) the cspec routes `this` through ECX.
        //    On x86 MinGW (`x86mingw`) the cspec keeps gcc's convention of
        //    passing `this` as a regular stack arg. Either way, when the cspec
        //    accepts `__thiscall` AND the function lives in a GhidraClass
        //    namespace, Ghidra injects a hidden `this: Class*` first parameter
        //    at render/display time.
        //
        // Track whether thiscall was actually accepted (some cspecs don't have
        // it) and whether the namespace is a class — those two together are
        // what decide whether Ghidra will inject `this` for us. Don't rely on
        // `func.getParameter(0)?.name == "this"` to detect it: for functions
        // we just force-created from a stab via CreateFunctionCmd, the
        // parameter list isn't populated until later analysis runs.
        val thiscallAccepted = runCatching { func.setCallingConvention("__thiscall") }
            .onFailure { log("method-calling-convention", "$className::${m.name}: ${it.message}") }
            .isSuccess
        val ghidraInjectsThis = thiscallAccepted && func.parentNamespace is GhidraClass

        // 4. Apply prototype from MethodDecl.signature.
        // gcc 3.x stabs encode `#`-form member functions as
        // `[this_ptr, p1, ..., pN, void_sentinel]`. FunctionT (free functions)
        // carries no inline params at all (they arrive via N_PSYM records), so
        // neither implicit `this` nor void sentinel applies there — both
        // adjustments are Method-only.
        val retDecl: TypeDecl<GlobalTypeId>
        val paramDecls: List<TypeDecl<GlobalTypeId>>
        // gcc emits MethodDecl.signature as Ref or InlineDef into a Method ast
        // (it's a separately-bound type id). Walk the wrappers before
        // pattern-matching so the common cases reach the Method/FunctionT
        // branches instead of falling through `else -> return`.
        when (val sig = unwrapSignature(m.signature)) {
            is TypeDecl.Method -> {
                retDecl = sig.ret
                paramDecls = if (ghidraInjectsThis) sig.params.drop(1) else sig.params
            }

            is TypeDecl.FunctionT -> {
                retDecl = sig.ret
                paramDecls = sig.params
            }

            else -> return
        }
        val ret = typeRegistry.dataTypeFor(retDecl)
        if (ret != null) func.setReturnType(ret, source)

        // Build resolved formal params, falling back to Undefined4 for any
        // stab-side TypeDecl we couldn't resolve. We used to early-return when
        // any param type was null and "keep the prior assignment"; that left
        // Ghidra's auto-guessed signature in place, and combined with the
        // newly-applied `__thiscall` (which prepends its own `this`), produced
        // a double-`this` like
        //   `void bouniaf::Dump(bouniaf *this, ushort this, uint dest)`
        // (the leading `this` is Ghidra's __thiscall injection; the second
        // `this` is the leftover guess named by autoanalysis). Always
        // replacing the formal-param list — even with Undefined4 for slots we
        // couldn't type — gives a clean `(this, Undefined4 arg0)` instead.
        val resolvedParams = paramDecls.map { typeRegistry.dataTypeFor(it) }
        // gcc encodes the end-of-args sentinel as void on every Method-style
        // signature; check the UNWRAPPED form, not `m.signature` directly
        // (gcc emits signatures wrapped in InlineDef / Ref, where the
        // wrapper isn't a Method itself). Also substitute mid-list voids
        // (defensive — void isn't a legal real param type) to keep
        // ParameterImpl happy below.
        val paramTypes = if (unwrapSignature(m.signature) is TypeDecl.Method) {
            resolvedParams.dropLastWhile { it is VoidDataType }
        } else {
            resolvedParams
        }.map { if (it is VoidDataType) Undefined4DataType.dataType else it }
        val unresolvedCount = paramTypes.count { it == null }
        if (unresolvedCount > 0) {
            paramTypes.forEachIndexed { i, pdt ->
                if (pdt == null) {
                    ctx.diagnostics.recordDegradation(
                        "method-param-unresolved",
                        "$className::${m.name}[$i]",
                        paramDecls.getOrNull(i)?.toString(),
                    )
                }
            }
        }
        // Build the full param list ourselves — explicit `this: Class*`
        // prefix when applicable, then the formal stab params — and apply via
        // DYNAMIC_STORAGE_ALL_PARAMS. This sidesteps the ambiguity around
        // DYNAMIC_STORAGE_FORMAL_PARAMS + __thiscall, which depending on
        // Ghidra version may or may not auto-prepend `this`, and which would
        // happily *rename* our `arg0` to `this` when the storage analyzer
        // placed it in the canonical this-storage slot — yielding the
        // duplicate-`this` displays we used to see.
        val classPtr = PointerDataType(structDt, dtm)
        val explicitThis = if (ghidraInjectsThis) {
            listOf(
                ParameterImpl(
                    "this",
                    classPtr,
                    program,
                    source,
                ),
            )
        } else {
            emptyList()
        }
        val formals = paramTypes.mapIndexed { i, pdt ->
            ParameterImpl(
                "arg$i",
                pdt ?: Undefined4DataType.dataType,
                program,
                source,
            )
        }
        func.replaceParameters(
            explicitThis + formals,
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true,
            source,
        )
    }

    /**
     * Map a ctor/dtor mangled name to its in-class display form. Returns null
     * for non-ctor/dtor methods (caller falls back to MethodDecl.name).
     *
     *   _ZN3FooC[123]E… → "Foo"
     *   _ZN3FooD[012]E… → "~Foo"
     *
     * Itanium emits up to three linker symbols per ctor (in-charge /
     * not-in-charge / allocating) and three per dtor (deleting / in-charge /
     * not-in-charge); all share the same source-level name. Ghidra's symbol
     * model allows multiple symbols with the same name in a namespace —
     * they're disambiguated by address — so we match the demangler's
     * convention and emit just `Foo` / `~Foo` rather than inventing
     * `_C1`/`_D1` suffixes.
     */
    private fun displayNameFor(mangled: String, className: String): String? {
        val ctorRe = Regex("""C[123]E[a-zA-Z_0-9$]*$""")
        val dtorRe = Regex("""D[012]E[a-zA-Z_0-9$]*$""")
        ctorRe.containsMatchIn(mangled).let { if (it) return className }
        dtorRe.containsMatchIn(mangled).let { if (it) return "~$className" }
        return null
    }

    private fun buildAndApplyVtable(
        className: String,
        body: TypeDecl.Struct<GlobalTypeId>,
        ns: GhidraClass,
        category: CategoryPath,
        structDt: Structure,
    ) {
        // 1. Walk inheritance chain to gather inherited virtuals first (Itanium ABI 32-bit:
        //    derived class's vtable starts with base-class entries, in declaration order
        //    of the base list, with overridden slots replaced by the derived method).
        val inherited = collectInheritedVirtuals(body)
        val ownVirtuals = body.methods
            .filter { it.virt == VirtKind.VIRTUAL }
            .sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
        // Merge: inherited slots first (in inheritance order), then any new ones
        // declared in this class. Overrides replace the inherited slot (matched by
        // signature name; cheap heuristic — sufficient for Cygwin gcc 3.4.4 single
        // inheritance, surfaces as a question for MI in Open Questions).
        val virtuals = mergeVtableSlots(inherited, ownVirtuals)
        if (virtuals.isEmpty()) {
            ctx.diagnostics.recordVtable(className, "skipped", reason = "no-virtuals")
            return
        }

        // 2. Build / look up two related structs:
        //   <Class>_vftable: the array of function pointers — what the {vfptr}
        //                    field in a polymorphic object points to. Lives under
        //                    `/ClassDataTypes/<Class>/` with each slot typed as
        //                    Pointer→FunctionDefinition(<method-signature>) so the
        //                    decompiler can resolve virtual calls; this matches
        //                    Ghidra's `RecoveredClassHelper` convention and lets
        //                    `ApplyClassFunctionSignatureUpdatesScript` (shift-S)
        //                    operate on our classes.
        //   <Class>_vtable:  the full record at `_ZTV<class>` — Itanium ABI prefix
        //                    (offset_to_top + rtti) followed by an embedded
        //                    <Class>_vftable at offset 2*ptrSize. Our own decoration,
        //                    sits next to the vftable in the same category.
        //
        // CRITICAL: dtm.addDataType returns the DTM-resolved instance; mutating the
        // local pre-add reference doesn't propagate. Always work through the resolved
        // reference.
        val classDataTypesRoot = CategoryPath(CategoryPath.ROOT, "ClassDataTypes")
        val vftableCategory = CategoryPath(classDataTypesRoot, className)
        val vftableName = "${className}_vftable"
        val vtableName = "${className}_vtable"
        val ptrSize = program.defaultPointerSize // typically 4 on 32-bit

        // a. Populate <Class>_vftable (the function pointer array).
        val vftable = typeRegistry.getOrRegister<Structure>(vftableCategory, vftableName) {
            StructureDataType(vftableCategory, vftableName, 0, dtm)
        }
        while (vftable.numComponents > 0) vftable.delete(0)
        for (m in virtuals) {
            val slotType = buildVirtualSlotType(m, className, vftableCategory) ?: run {
                ctx.diagnostics.recordDegradation(
                    "vftable-slot-untyped",
                    "$className::${m.name}",
                )
                PointerDataType.getPointer(Undefined4DataType.dataType, dtm)
            }
            vftable.add(slotType, ptrSize, m.name, "virtual ${m.name}")
        }

        // b. Build <Class>_vtable wrapping that.
        val vtable = typeRegistry.getOrRegister<Structure>(vftableCategory, vtableName) {
            StructureDataType(vftableCategory, vtableName, 0, dtm)
        }
        while (vtable.numComponents > 0) vtable.delete(0)
        val intPtrDt = if (ptrSize == 8) {
            LongLongDataType.dataType
        } else {
            IntegerDataType.dataType
        }
        vtable.add(intPtrDt, ptrSize, "offset_to_top", "offset to top of complete object")
        val typeinfoPtr = PointerDataType.getPointer(Undefined4DataType.dataType, dtm)
        vtable.add(typeinfoPtr, ptrSize, "rtti", "_ZTI$className typeinfo pointer")
        vtable.add(vftable, vftable.length, "vftable", "virtual function table")

        // 3. Resolve _ZTV<class> address with fallbacks.
        val candidates = VtableSymbolCandidates.mangledZtvCandidates(className)

        // If class name contains template args, log the limitation before trying resolution
        if ('<' in className) {
            log("vtable-templated-skip", "class '$className' has template args; _ZTV lookup unsupported in v1")
        }

        val addr = resolveVtableAddress(className, body, candidates) ?: return

        // 4. Apply data at the address.
        program.listing.clearCodeUnits(addr, addr.add(vtable.length.toLong() - 1), false)
        program.listing.createData(addr, vtable)
        // Add a `vftable` label in the class namespace alongside whatever
        // demangled `_ZTV<class>` produced. `RecoveredClassHelper` (and
        // `ApplyClassFunctionSignatureUpdatesScript`) requires a symbol whose
        // name contains "vftable" at the address of the Data containing the
        // virtual-function refs — without it the shift-S round-trip can't
        // locate the vftable. The demangler typically emits `<class>::vtable`
        // (no f), so this label is what makes us discoverable.
        runCatching { symtab.createLabel(addr, "vftable", ns, source) }
            .onFailure { log("vftable-label-failed", "$className at $addr: ${it.message}") }
        log("vtable", "applied $vtableName", address = addr)
        ctx.diagnostics.recordVtable(className, "applied")

        // 5. Plate-comment each virtual method. An unresolved mangled name
        // here is *not* a vtable failure — it's the expected shape for a
        // pure virtual (gcc's vtable slot points at `__cxa_pure_virtual`
        // and emits no symbol for the declaration) or for a method whose
        // implementation lives in an external DLL the binary imports. The
        // slot type was already typed from the stabs signature in step a;
        // we just can't anchor a comment without a target Function.
        // First function pointer sits after the offset-to-top + rtti prefix.
        var off = (2L * ptrSize)
        for (m in virtuals) {
            val mAddr = m.mangled?.let(resolver::resolve)
            if (mAddr != null) {
                val func = program.functionManager.getFunctionAt(mAddr)
                if (func != null) {
                    program.listing.setComment(
                        func.entryPoint,
                        CommentType.PLATE,
                        "virtual ${m.name}; ${className}_vtable offset $off",
                    )
                } else {
                    ctx.diagnostics.inc("vtable-virtual-no-function")
                    log(
                        "vtable-virtual-no-function",
                        "no Function at $mAddr for virtual method ${m.name} in $className",
                        Level.DEBUG,
                    )
                }
            } else {
                // Pure virtual or import-resident — both expected.
                ctx.diagnostics.inc("vtable-virtual-no-impl")
                log(
                    "vtable-virtual-no-impl",
                    "virtual method '${m.name}' in $className has no resolvable implementation " +
                        "(pure virtual or DLL import); slot type still applied",
                    Level.DEBUG,
                )
            }
            off += ptrSize
        }
    }

    /**
     * Build the typed function-pointer slot for [m] in `<Class>_vftable`:
     * `Pointer → FunctionDefinition(<actual signature>)`. Following Ghidra's
     * `RecoveredClassHelper` convention, the first param `this: Class*` (if
     * present from `__thiscall` injection) is rewritten to `void*` so the
     * resulting pointer type is reusable across the inheritance chain
     * (parent slots can hold pointers to derived overrides).
     *
     * Returns null if the method's address can't be resolved or the function
     * isn't present — caller falls back to a generic `Pointer→Undefined4`.
     */
    /**
     * Wrap the *already-materialised* FunctionDefinition for [m] in a
     * Pointer. `m.signature` is a Ref/InlineDef into a Method ast that
     * [TypeRegistry] resolved in passB; the FunctionDefinition there already
     * carries `__thiscall` and `this: <Class>*`, so the slot is just a
     * pointer to it — no re-build, no recalibration of this.
     */
    /**
     * Walk Ref/InlineDef wrappers to the underlying Method or FunctionT decl.
     * gcc binds method signatures to their own type ids, so the value carried
     * on [MethodDecl.signature] is typically `Ref(id)` or `InlineDef(id, …)`,
     * not the bare Method/FunctionT.
     */
    private fun unwrapSignature(sig: TypeDecl<GlobalTypeId>): TypeDecl<GlobalTypeId>? {
        var cur: TypeDecl<GlobalTypeId>? = sig
        while (cur != null) {
            when (cur) {
                is TypeDecl.Method, is TypeDecl.FunctionT -> return cur
                is TypeDecl.Ref -> cur = harvest.getType(cur.id)?.body
                is TypeDecl.InlineDef -> cur = cur.body
                else -> return null
            }
        }
        return null
    }

    /**
     * Build a class-scoped FunctionDefinition for [m] and wrap it in a Pointer.
     * The vftable struct's slot field is named after the method (e.g.
     * `GetInstType`) and the pointee FD is named the same so the two line up
     * — see the `atLeastOneVtableStructApplied` regression invariant.
     *
     * `this` is the declaring class's pointer when resolvable, void* otherwise.
     * Calling convention is `__thiscall` if the program supports it (mingw /
     * x86win32); the lookup silently downgrades on platforms without it.
     */
    private fun buildVirtualSlotType(
        m: MethodDecl<GlobalTypeId>,
        className: String,
        classCategory: CategoryPath,
    ): PointerDataType? {
        val unwrapped = unwrapSignature(m.signature)
        val method = unwrapped as? TypeDecl.Method<GlobalTypeId> ?: run {
            ctx.diagnostics.recordDegradation(
                "vftable-slot-signature-not-method",
                "$className::${m.name}",
                "unwrapped=${unwrapped?.let { it::class.simpleName } ?: "null"} sig=${m.signature}",
            )
            return null
        }
        val funcDef = typeRegistry.buildFunctionDefinition(
            category = classCategory,
            name = m.name,
            ret = method.ret,
            params = method.params,
            thisType = typeRegistry.dataTypeFor(method.cls) ?: PointerDataType(VoidDataType(), dtm),
            callingConvention = "__thiscall",
            at = "$className::${m.name}",
        )
        val resolved = typeRegistry.register(funcDef) as FunctionDefinition
        return PointerDataType(resolved, dtm)
    }

    /**
     * Resolve the address of a vtable struct for [className], trying multiple
     * fallback strategies:
     * 1. Direct resolution via AddressResolver using [candidates] list
     * 2. Symbol-table scan for _ZTV-prefixed symbols that decode to className
     * 3. Memory scan of .rdata block for matching symbols
     *
     * Returns the resolved address or null (caller handles the bail-out and bucketing).
     */
    private fun resolveVtableAddress(
        className: String,
        body: TypeDecl.Struct<GlobalTypeId>,
        candidates: List<String>,
    ): Address? {
        // Step 1: Try direct resolver lookup
        candidates.firstNotNullOfOrNull { resolver.resolve(it) }?.let { return it }

        // Step 2: Fallback to symbol-table scan
        try {
            symtab.symbolIterator.firstOrNull {
                (it.name.startsWith("_ZTV") || it.name.startsWith("__ZTV")) &&
                    VtableSymbolCandidates.decodesToClass(program, it.name, className)
            }?.let { return it.address }
        } catch (e: IllegalArgumentException) {
            log("vtable-symbol-scan-error", "exception scanning symbol table for $className: ${e.message}")
        }

        // Step 3: Fallback to .rdata memory scan
        val rdataBlock = program.memory.getBlock(".rdata")
        if (rdataBlock != null) {
            try {
                symtab.getSymbolIterator(rdataBlock.start, true)
                    .asIterable()
                    .takeWhile { it.address < rdataBlock.end }
                    .firstOrNull {
                        (it.name.startsWith("_ZTV") || it.name.startsWith("__ZTV")) &&
                            VtableSymbolCandidates.decodesToClass(program, it.name, className)
                    }?.let { return it.address }
            } catch (e: IllegalArgumentException) {
                log("vtable-rdata-scan-error", "exception scanning .rdata for $className: ${e.message}")
            }
        }

        // All resolution attempts failed: bucket the failure
        val failureBucket = when {
            '<' in className -> "templated-unsupported"

            body.hasVTablePointerMarker && body.methods.none { it.virt == VirtKind.VIRTUAL } ->
                "no-virtual-methods-flagged-but-marker-set"

            else -> "truly-missing"
        }
        ctx.diagnostics.recordVtable(className, "failed", failureBucket)
        log(
            "vtable-failed-$failureBucket",
            "class '$className': vtable not found (tried ${candidates.joinToString()})",
        )

        return null
    }

    /**
     * Recursively gather virtual methods from each base subobject, walking the full
     * inheritance chain (base of base of base…). Returns the merged list in vtable
     * slot order: a derived class's vtable contains ALL virtuals visible through the
     * type, with overrides replacing inherited slots by name (cheap heuristic;
     * sufficient for non-overloaded virtuals in the Cygwin gcc 3.4.4 corpus —
     * for full Itanium override matching we'd compare parameter types).
     *
     * Without recursion we'd miss virtuals from grand-bases (e.g. bouniaf → ExprInst
     * → bouniaf → Inst: Inst::GetOffset is in bouniaf's vtable but not in ExprInst's
     * direct `methods` list).
     */
    private fun collectInheritedVirtuals(body: TypeDecl.Struct<GlobalTypeId>): List<MethodDecl<GlobalTypeId>> {
        val out = mutableListOf<MethodDecl<GlobalTypeId>>()
        val visited = mutableSetOf<TypeDecl.Struct<GlobalTypeId>>()
        gatherTransitive(body, out, visited)
        return out.sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
    }

    private fun gatherTransitive(
        body: TypeDecl.Struct<GlobalTypeId>,
        out: MutableList<MethodDecl<GlobalTypeId>>,
        visited: MutableSet<TypeDecl.Struct<GlobalTypeId>>,
    ) {
        for (base in body.bases) {
            val baseStruct = ClassBuilderHelpers(typeResolver).resolveBaseAstStatic(base.type)
                ?: continue
            if (!visited.add(baseStruct)) continue
            // Depth-first: grand-base virtuals come before direct-base's own additions,
            // matching the order they appear in the derived vtable.
            gatherTransitive(baseStruct, out, visited)
            for (m in baseStruct.methods.filter { it.virt == VirtKind.VIRTUAL }) {
                val idx = out.indexOfFirst { it.name == m.name }
                if (idx >= 0) out[idx] = m else out += m
            }
        }
    }

    /**
     * Apply derived overrides on top of the inherited slot list (override = same
     * simple name as an inherited entry). Sufficient for non-overloaded virtuals
     * in the Cygwin gcc 3.4.4 corpus; full Itanium override matching would need
     * parameter-type comparison.
     */
    private fun mergeVtableSlots(
        inherited: List<MethodDecl<GlobalTypeId>>,
        own: List<MethodDecl<GlobalTypeId>>,
    ): List<MethodDecl<GlobalTypeId>> {
        val result = inherited.toMutableList()
        for (m in own) {
            val idx = result.indexOfFirst { it.name == m.name }
            if (idx >= 0) result[idx] = m else result += m
        }
        return result
    }

    /**
     * Returns the lowest-offset polymorphic base subobject of `body`, or null if none.
     * "Polymorphic" = has its own vtable pointer marker, has a virtual method, or
     * recursively has a polymorphic base. Used to determine whether a derived class
     * inherits its vfptr slot from a base (no need to insert one) and at what offset.
     *
     * Delegates to the static ClassBuilderHelpers version which is the single source of truth.
     */
    internal fun firstPolymorphicBase(body: TypeDecl.Struct<GlobalTypeId>): BaseDecl<GlobalTypeId>? =
        ClassBuilderHelpers(typeResolver).firstPolymorphicBase(body)

    internal fun hasPolymorphicBaseSubobject(body: TypeDecl.Struct<GlobalTypeId>): Boolean =
        ClassBuilderHelpers(typeResolver).hasPolymorphicBaseSubobject(body)

    /**
     * Itanium-mangled compiler-implicit special members the compiler typically omits
     * when they are trivial. Pattern: `_ZN<class>` followed by `C[123]` (ctor variant),
     * `D[012]` (dtor variant), or `aSE` (operator=), followed by `v` (void / no params,
     * i.e. default-constructible) or `RKS_` (const-ref-to-Self, i.e. copy) or
     * `OS_` (rvalue-ref-to-Self, i.e. move).
     */
    private fun isLikelyImplicitTrivialSpecialMember(mangled: String): Boolean {
        if (!mangled.startsWith("_ZN")) return false
        return IMPLICIT_SPECIAL_MEMBER_TAIL.containsMatchIn(mangled)
    }

    companion object {
        // Itanium tail:  <special-mnemonic> 'E' <params>
        //   C[123] = constructor variants (in-charge / not-in-charge / allocating)
        //   D[012] = destructor variants (deleting / in-charge / not-in-charge)
        //   aS     = operator=
        //   'E' closes the nested-name; params: 'v' = (), 'RKS_' = (const Self&),
        //   'OS_' = (Self&&).
        private val IMPLICIT_SPECIAL_MEMBER_TAIL =
            Regex("""(?:C[123]|D[012]|aS)E(?:v|RKS_|OS_)$""")
    }
}
