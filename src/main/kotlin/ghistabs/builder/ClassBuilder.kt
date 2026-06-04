package ghistabs.builder

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.diag.DiagnosticSink
import ghistabs.importer.ImportContext
import ghistabs.parser.*

class TypeResolver(typeAsts: List<TypeAst>, private val fileResolver: FileResolver) {
    /** All type ASTs indexed by TypeId for inheritance resolution. */
    val typeAstsById = typeAsts.associateBy { it.id }

    /** All struct ASTs harvested in Pass A, indexed by name. */
    val structAstsByName = typeAsts.mapNotNull { ast ->
        (ast.body as? TypeDecl.Struct)?.let { ast.name to it }
    }.toMap()

    fun getTypeFor(id: LocalTypeId, src: SourceFile) = fileResolver.globalIdFor(id, src)?.let {
        typeAstsById[it]
    }

    inline fun <reified T : TypeDecl> getBodyFor(id: LocalTypeId, src: SourceFile) = getTypeFor(id, src)?.let {
        it.body as? T
    }

    fun getStructByName(name: String) = structAstsByName[name]
}

/**
 * Static helpers for polymorphic base detection (extracted for pure unit testing).
 */
internal class ClassBuilderHelpers(val resolver: TypeResolver) {
    fun hasPolymorphicBaseSubobject(src: SourceFile, body: TypeDecl.Struct) = firstPolymorphicBase(src, body) != null

    fun firstPolymorphicBase(src: SourceFile, body: TypeDecl.Struct): BaseDecl? = body.bases
        .sortedBy { it.offsetBits }
        .firstOrNull { base ->
            val baseStruct =
                resolveBaseAstStatic(src, base.type) ?: return@firstOrNull false
            baseStruct.hasVTablePointerMarker ||
                baseStruct.methods.any { it.virt == VirtKind.VIRTUAL } ||
                firstPolymorphicBase(src, baseStruct) != null
        }

    fun resolveBaseAstStatic(src: SourceFile, typeDecl: TypeDecl): TypeDecl.Struct? = when (typeDecl) {
        // Look up by TypeId using the byId map
        is TypeDecl.Ref -> resolver.getBodyFor<TypeDecl.Struct>(typeDecl.id, src)

        // Cross-reference by tagName: look in structAstsByName
        is TypeDecl.XRef -> resolver.getStructByName(typeDecl.tagName)

        // Inline definition: prefer the materialised AST at this id (real struct body), fall
        // back to the inline body. The inline body is often a forward XRef stub whose Struct
        // form lives at typeAstsById[typeDecl.id] — without this fallback, base polymorphism
        // detection misses inherited vfptrs (e.g. DCInst → InlineDef(ExprInst id, XRef body)).
        is TypeDecl.InlineDef -> resolver.getBodyFor<TypeDecl.Struct>(typeDecl.id, src)
            ?: (typeDecl.body as? TypeDecl.Struct)
            ?: resolveBaseAstStatic(src, typeDecl.body)

        else -> null
    }
}

class ClassBuilder(
    private val typeRegistry: TypeRegistry,
    private val typeResolver: TypeResolver,
    private val ctx: ImportContext<*>,
) : DiagnosticSink by ctx.sink {
    private val source = SourceType.IMPORTED
    private val program = ctx.program
    private val resolver = ctx.resolver
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

    /** Materialise a class struct + namespace + (optional) vtable struct + apply at _ZTV. */
    fun build(src: SourceFile, name: String, body: TypeDecl.Struct, category: CategoryPath) {
        // 1. Locate the materialised Structure in the DTM.
        // (typeRegistry.dataTypeFor does not handle TypeDecl.Struct — Structs are only
        // looked up by TypeId via materialiseAll; here we resolve by (category, name).)
        val structDt = (dtm.getDataType(category, name) as? Structure) ?: run {
            log("class-not-struct", "skipping non-struct class '$name' at $category")
            return
        }

        // 2. Insert {vfptr} first if class is polymorphic.
        val isPoly = body.hasVTablePointerMarker ||
            body.methods.any { it.virt == VirtKind.VIRTUAL } ||
            body.fields.any {
                it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr"
            }
        if (isPoly) ensureVfptrFirstField(src, structDt, body, name, category)

        // 3. Create or upgrade the GhidraClass namespace.
        val ns = ensureClassNamespace(name)

        // 4. Re-parent member functions.
        for (m in body.methods) reparentMethod(src, m, name, ns, structDt)

        // 5. If polymorphic: build <Class>_vtable struct + apply at _ZTV<class> address.
        if (isPoly) buildAndApplyVtable(src, name, body, ns, category, structDt)
    }

    private fun ensureClassNamespace(name: String): GhidraClass {
        // Split `Foo::Bar::Baz` and walk/create each segment.
        val parts = name.split("::").filter { it.isNotEmpty() }
        var parent: Namespace? = null
        for ((i, part) in parts.withIndex()) {
            val isLast = i == parts.lastIndex
            val existing = symtab.getNamespace(part, parent)
            parent = when (existing) {
                null if isLast -> symtab.createClass(parent, part, source)
                null -> symtab.createNameSpace(parent, part, source)
                else if (isLast && existing !is GhidraClass) ->
                    ghidra.app.util.NamespaceUtils.convertNamespaceToClass(existing)

                else -> existing
            }
        }
        return parent as GhidraClass
    }

    private fun ensureVfptrFirstField(
        src: SourceFile,
        structDt: Structure,
        body: TypeDecl.Struct,
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
            hasPolymorphicBaseSubobject = hasPolymorphicBaseSubobject(src, body),
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
        val struct = dtm.getDataType(vftableCategory, name) ?: dtm.addDataType(
            StructureDataType(vftableCategory, name, 0, dtm),
            DataTypeConflictHandler.KEEP_HANDLER,
        )
        return PointerDataType.getPointer(struct, dtm)
    }

    private fun reparentMethod(
        src: SourceFile,
        m: MethodDecl,
        className: String,
        ns: GhidraClass,
        structDt: Structure,
    ) {
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
                log("unresolved-symbol", "method $mangled (in $className)")
            }
            return
        }
        val func = program.functionManager.getFunctionAt(addr) ?: run {
            log("unresolved-symbol", "no Function at $addr for $mangled")
            return
        }

        // 1. Re-parent.
        func.parentNamespace = ns

        // 2. Choose the in-class display name:
        val displayName = displayNameFor(mangled, className) ?: m.name
        if (func.name != displayName) func.setName(displayName, source)

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
        val retDecl: TypeDecl
        val paramDecls: List<TypeDecl>
        when (val sig = m.signature) {
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
        val ret = typeRegistry.dataTypeFor(retDecl, src)
        if (ret != null) func.setReturnType(ret, source)

        // Build resolved formal params, falling back to Undefined4 for any
        // stab-side TypeDecl we couldn't resolve. We used to early-return when
        // any param type was null and "keep the prior assignment"; that left
        // Ghidra's auto-guessed signature in place, and combined with the
        // newly-applied `__thiscall` (which prepends its own `this`), produced
        // a double-`this` like
        //   `void XapArgRegLdStInst::Dump(XapArgRegLdStInst *this, ushort this, uint dest)`
        // (the leading `this` is Ghidra's __thiscall injection; the second
        // `this` is the leftover guess named by autoanalysis). Always
        // replacing the formal-param list — even with Undefined4 for slots we
        // couldn't type — gives a clean `(this, Undefined4 arg0)` instead.
        val resolvedParams = paramDecls.map { typeRegistry.dataTypeFor(it, src) }
        val paramTypes = if (m.signature is TypeDecl.Method) {
            resolvedParams.dropLastWhile { it is VoidDataType }
        } else {
            resolvedParams
        }
        val unresolvedCount = paramTypes.count { it == null }
        if (unresolvedCount > 0) {
            ctx.diagnostics.inc("method-param-unresolved", unresolvedCount.toLong())
            if (paramTypes.isNotEmpty()) {
                log(
                    "method-param-unresolved",
                    "$className::${m.name}: $unresolvedCount/${paramTypes.size} stab param types " +
                        "unresolved; substituting Undefined4 so __thiscall `this` injection isn't " +
                        "shadowed by leftover autoanalysis params",
                )
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
                ghidra.program.model.listing.ParameterImpl(
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
            ghidra.program.model.listing.ParameterImpl(
                "arg$i",
                pdt ?: Undefined4DataType.dataType,
                program,
                source,
            )
        }
        func.replaceParameters(
            explicitThis + formals,
            ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true,
            source,
        )
    }

    /**
     * Map a ctor/dtor mangled name to its in-class display form. Returns null
     * for non-ctor/dtor methods (caller falls back to MethodDecl.name).
     *
     *   _ZN3FooC1Ev → "Foo_C1"   (in-charge ctor)
     *   _ZN3FooC2Ev → "Foo_C2"   (not-in-charge ctor)
     *   _ZN3FooC3Ev → "Foo_C3"   (allocating ctor)
     *   _ZN3FooD0Ev → "~Foo_D0"  (deleting dtor)
     *   _ZN3FooD1Ev → "~Foo_D1"  (in-charge dtor)
     *   _ZN3FooD2Ev → "~Foo_D2"  (not-in-charge dtor)
     *
     * If only one variant exists in the binary we still suffix; the design says
     * "_C1/_C2/_C3 suffixes to disambiguate when multiple linker symbols exist".
     * We always suffix because we don't yet know how many variants exist; pruning
     * happens later (or never — the suffixes are harmless).
     */
    private fun displayNameFor(mangled: String, className: String): String? {
        // Match Itanium-ABI ctor/dtor encoding: _ZN…C[123]Ev?… or _ZN…D[012]Ev?…
        // The variant digit is followed by parameter encoding (E, Ev, etc).
        val ctorRe = Regex("""C([123])E[a-zA-Z_0-9$]*$""")
        val dtorRe = Regex("""D([012])E[a-zA-Z_0-9$]*$""")
        ctorRe.find(mangled)?.let { return "${className}_C${it.groupValues[1]}" }
        dtorRe.find(mangled)?.let { return "~${className}_D${it.groupValues[1]}" }
        return null
    }

    private fun buildAndApplyVtable(
        src: SourceFile,
        className: String,
        body: TypeDecl.Struct,
        ns: GhidraClass,
        category: CategoryPath,
        structDt: Structure,
    ) {
        // 1. Walk inheritance chain to gather inherited virtuals first (Itanium ABI 32-bit:
        //    derived class's vtable starts with base-class entries, in declaration order
        //    of the base list, with overridden slots replaced by the derived method).
        val inherited = collectInheritedVirtuals(src, body)
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
        val vftable = (dtm.getDataType(vftableCategory, vftableName) as? Structure) ?: (
            dtm.addDataType(
                StructureDataType(vftableCategory, vftableName, 0, dtm),
                DataTypeConflictHandler.KEEP_HANDLER,
            ) as Structure
            )
        while (vftable.numComponents > 0) vftable.delete(0)
        for (m in virtuals) {
            val slotType = buildVirtualSlotType(m, className, vftableCategory) ?: run {
                ctx.diagnostics.inc("vftable-slot-fallback-untyped")
                PointerDataType.getPointer(Undefined4DataType.dataType, dtm)
            }
            vftable.add(slotType, ptrSize, m.name, "virtual ${m.name}")
        }

        // b. Build <Class>_vtable wrapping that.
        val vtable = (dtm.getDataType(vftableCategory, vtableName) as? Structure) ?: (
            dtm.addDataType(
                StructureDataType(vftableCategory, vtableName, 0, dtm),
                DataTypeConflictHandler.KEEP_HANDLER,
            ) as Structure
            )
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
        log("vtable", "applied $vtableName", addr)
        ctx.diagnostics.recordVtable(className, "applied")

        // 5. Plate-comment each virtual method.
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
                    log(
                        "vtable-virtual-unresolved",
                        "no Function at $mAddr for virtual method ${m.name} in $className",
                    )
                    ctx.diagnostics.recordVtable(className, "failed", reason = "virtual-method-unresolved")
                }
            } else {
                log(
                    "vtable-virtual-unresolved",
                    "virtual method '${m.name}' in $className: no mangled symbol or unresolved address",
                )
                ctx.diagnostics.recordVtable(className, "failed", reason = "virtual-method-unresolved")
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
    private fun buildVirtualSlotType(m: MethodDecl, className: String, classCategory: CategoryPath): PointerDataType? {
        val mAddr = m.mangled?.let(resolver::resolve) ?: return null
        val func = program.functionManager.getFunctionAt(mAddr) ?: return null
        val funcDef = FunctionDefinitionDataType(func, false)
        // Name the FunctionDefinition after the in-class display name, not
        // the function's possibly-mangled-or-class-namespaced full name.
        runCatching { funcDef.name = m.name }
        // Rewrite the auto-injected `this: <Class>*` (from __thiscall) to
        // void* so this slot's type doesn't pin the pointer to one concrete
        // class — overrides in derived classes can still share the slot.
        val args = funcDef.arguments
        if (args.isNotEmpty() && args[0].name == "this") {
            val voidPtr = PointerDataType(VoidDataType(), dtm)
            args[0].dataType = voidPtr
        }
        funcDef.categoryPath = classCategory
        val resolved = dtm.addDataType(funcDef, DataTypeConflictHandler.KEEP_HANDLER) as FunctionDefinition
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
    private fun resolveVtableAddress(className: String, body: TypeDecl.Struct, candidates: List<String>): Address? {
        // Step 1: Try direct resolver lookup
        candidates.firstNotNullOfOrNull { resolver.resolve(it) }?.let { return it }

        // Step 2: Fallback to symbol-table scan
        try {
            symtab.symbolIterator.firstOrNull {
                (it.name.startsWith("_ZTV") || it.name.startsWith("__ZTV")) &&
                    VtableSymbolCandidates.itaniumDecodesToClass(it.name, className)
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
                            VtableSymbolCandidates.itaniumDecodesToClass(it.name, className)
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
     * Without recursion we'd miss virtuals from grand-bases (e.g. DCInst → ExprInst
     * → XapInst → Inst: Inst::GetOffset is in DCInst's vtable but not in ExprInst's
     * direct `methods` list).
     */
    private fun collectInheritedVirtuals(src: SourceFile, body: TypeDecl.Struct): List<MethodDecl> {
        val out = mutableListOf<MethodDecl>()
        val visited = mutableSetOf<TypeDecl.Struct>()
        gatherTransitive(src, body, out, visited)
        return out.sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
    }

    private fun gatherTransitive(
        src: SourceFile,
        body: TypeDecl.Struct,
        out: MutableList<MethodDecl>,
        visited: MutableSet<TypeDecl.Struct>,
    ) {
        for (base in body.bases) {
            val baseStruct = ClassBuilderHelpers(typeResolver).resolveBaseAstStatic(src, base.type)
                ?: continue
            if (!visited.add(baseStruct)) continue
            // Depth-first: grand-base virtuals come before direct-base's own additions,
            // matching the order they appear in the derived vtable.
            gatherTransitive(src, baseStruct, out, visited)
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
    private fun mergeVtableSlots(inherited: List<MethodDecl>, own: List<MethodDecl>): List<MethodDecl> {
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
    internal fun firstPolymorphicBase(src: SourceFile, body: TypeDecl.Struct): BaseDecl? =
        ClassBuilderHelpers(typeResolver).firstPolymorphicBase(src, body)

    internal fun hasPolymorphicBaseSubobject(src: SourceFile, body: TypeDecl.Struct): Boolean =
        ClassBuilderHelpers(typeResolver).hasPolymorphicBaseSubobject(src, body)

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
