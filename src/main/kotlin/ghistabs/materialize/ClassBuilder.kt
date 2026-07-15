package ghistabs.materialize

import ghidra.app.util.NamespaceUtils
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.applyDemangling
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.degradation
import ghistabs.harvest.CanonicalGroup
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.materialize.itanium.*
import ghistabs.namespaceChain
import ghistabs.parse.*

class ClassBuilder(
    private val typeRegistry: TypeRegistry,
    private val harvest: Harvest,
    private val typeResolver: TypeResolver,
    private val ctx: ImportContext<*>,
) : DiagnosticSink by ctx {
    private val program = ctx.program
    private val resolver = ctx.resolver
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

    companion object {
        private val source = SourceType.IMPORTED

        // Injected/hidden params that must not be mistaken for source-level formals when
        // harvesting N_PSYM names: Ghidra's __thiscall `this` and StructReturnAnalyzer's
        // by-value return pointer.
        private val HIDDEN_PARAM_NAMES = setOf("this", "__return_storage_ptr__")
        fun CanonicalGroup.isClass() = ast.body is TypeDecl.Struct &&
            (
                ast.body.methods.isNotEmpty() ||
                    ast.body.hasVTablePointerMarker ||
                    // gcc 12 emits the vfptr as a regular `_vptr.XX` field instead of the
                    // `~%<id>;` marker hasVTablePointerMarker watches for — without this check
                    // every polymorphic class in xmltest would be skipped.
                    ast.body.fields.any { Itanium.isVptrField(it.name) }
                )

        private val CanonicalGroup.classBody get() = ast.body as TypeDecl.Struct<GlobalTypeId>
        private val CanonicalGroup.className get() = key.name

        // <Class>_vftable under /ClassDataTypes/<Class>/ — the function-pointer array {vfptr}
        // points at, laid at the vtable's address point (_ZTV + 2*ptrSize). Each slot is
        // Pointer→FunctionDefinition(<sig>) so the decompiler resolves virtual calls and
        // RecoveredClassHelper / shift-S round-trip. The offset_to_top + rtti header words sit
        // before the address point as plain Data (no enclosing struct — see buildAndApplyVtable).
        private val CanonicalGroup.vftableCategory get() = CategoryPath(Itanium.classDataTypesRoot, className)
        private val CanonicalGroup.vftableName get() = "${className}_vftable"
    }

    private val CanonicalGroup.vftable
        get() = typeRegistry.getOrRegister<Structure>(vftableCategory, vftableName) {
            StructureDataType(vftableCategory, vftableName, 0, dtm)
        }

    /**
     * {vfptr} points at the function-pointer array at the vtable's address point
     * (`_ZTV<class> + 2*ptrSize`), not at the record start. Modelled as `<Class>_vftable*`
     * under `/ClassDataTypes/<Class>/` so `RecoveredClassHelper` / shift-S round-trip
     * can find it.
     */
    private fun CanonicalGroup.ensureVtableTypeAndPointer(): Pointer = PointerDataType.getPointer(vftable, dtm)

    /**
     * Build every class/vtable group once. Each class header included by N CUs produces N TypeAsts
     * with distinct ids but identical ghidraName (xapasmcsr: 86 names duplicated up to 11x);
     * materialiseAll already collapsed by name, and iterating canonical groups builds each class
     * once, off the most-detailed body. Returns the number of classes built.
     */
    fun buildAll(): Int {
        val classes = typeResolver.byCanonicalKey.values.filter { it.isClass() }
        ctx.monitor.initialize(classes.size.toLong(), "Stabs: building classes")
        var built = 0
        for (group in classes) {
            ctx.monitor.increment()
            try {
                build(group)
                built++
            } catch (t: Throwable) {
                err("class-apply-error", "${group.key}: ${t.message}")
            }
        }
        return built
    }

    /** Materialise class struct + namespace + (optional) vtable struct, apply at _ZTV. */
    fun build(group: CanonicalGroup): Unit = group.run {
        val category = key.category
        val structDt = typeRegistry.dataTypeFor(ast.id)
        if (structDt !is Structure) {
            warn(
                "class-not-struct",
                "skipping ${structDt?.let { it::class.simpleName }} class '$className' at $category",
            )
            return
        }

        // A derived class inherits its base's vtable without re-marking the overrides virtual
        // (gcc 3.4.4: CPackedSegList's GetSeg/AddSeg are `virt=NORMAL`), so a polymorphic base
        // subobject is itself the signal — without it buildAndApplyVtable never runs and _ZTV<class>
        // is left unannotated. Virtuals.process walks bases, so the slots still resolve.
        val isPoly = classBody.hasVTablePointerMarker ||
            classBody.methods.any { it.virt == VirtKind.VIRTUAL } ||
            classBody.fields.any { Itanium.isVptrField(it.name) } ||
            typeResolver.hasPolymorphicBaseSubobject(classBody)
        if (isPoly) ensureVfptrFirstField(structDt)

        val ns = ensureClassNamespace()
        for (m in classBody.methods) reparentMethod(m, ns, structDt)
        if (isPoly) buildAndApplyVtable(ns)
    }

    /**
     * Derive the class's namespace chain. Prefers demangling a method's Itanium symbol
     * (handles templates) over splitting the source-form name (handles classes with no
     * methods or unmangleable symbols).
     */
    private fun CanonicalGroup.ensureClassNamespace(): GhidraClass {
        val parts = classBody.methods.firstNotNullOfOrNull { it.mangled }
            ?.let { namespaceChain(it) }
            ?: splitQualified(className)
        return buildNamespaceChain(parts.filter { it.isNotEmpty() })
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

    private fun CanonicalGroup.ensureVfptrFirstField(structDt: Structure) {
        val vfptrName = ClassUtils.VFPTR
        val parserVptrOffset = classBody.fields
            .firstOrNull { Itanium.isVptrField(it.name) }
            ?.let { (it.offsetBits / 8).toInt() }

        val targetOffset = parserVptrOffset ?: 0
        val existingComp = runCatching { structDt.getComponentAt(targetOffset) }.getOrNull()
        val snapshot = existingComp?.let {
            FirstComponentSnapshot(
                fieldName = it.fieldName,
                offsetBytes = it.offset,
                isUndefined = it.dataType is Undefined1DataType,
            )
        }

        val action = Layout.chooseVfptrAction(
            hasPolymorphicBaseSubobject = typeResolver.hasPolymorphicBaseSubobject(classBody),
            parserVptrOffsetBytes = parserVptrOffset,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = vfptrName,
        )

        when (action) {
            is VfptrAction.SkipInheritedFromBase -> debug("vfptr-inherited-from-base")

            is VfptrAction.AlreadyCanonical -> return

            is VfptrAction.Insert -> {
                val ptrToVtable = ensureVtableTypeAndPointer()
                structDt.insertAtOffset(
                    action.offsetBytes,
                    ptrToVtable,
                    ptrToVtable.length,
                    vfptrName,
                    "vtable pointer",
                )
                debug("vfptr-inserted")
            }

            is VfptrAction.Replace -> {
                val ptrToVtable = ensureVtableTypeAndPointer()
                structDt.replaceAtOffset(
                    action.offsetBytes,
                    ptrToVtable,
                    ptrToVtable.length,
                    vfptrName,
                    "vtable pointer (was: ${action.wasFieldName})",
                )
                debug("vfptr-normalized")
            }

            is VfptrAction.CollisionAt -> warn(
                "vfptr-collision",
                "$className: cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})",
            )
        }
    }

    private fun CanonicalGroup.reparentMethod(m: MethodDecl<GlobalTypeId>, ns: GhidraClass, structDt: Structure) {
        val mangled = m.mangled ?: run {
            log("method-no-mangled", "$className::${m.name}: stab has no mangled symbol")
            return
        }
        val addr = resolver.resolve(mangled) ?: run {
            // Trivial implicit special members (default ctor, copy/move ctor/assignment, dtor)
            // appear in every class's stab list but get no emitted symbol. Bucket separately
            // so the unresolved-symbol log surfaces real problems.
            if (isImplicitTrivialSpecialMember(mangled)) {
                debug("method-implicit-not-emitted")
            } else {
                debug("unresolved-symbol", "method $mangled (in $className)")
            }
            return
        }
        val func = program.functionManager.getFunctionAt(addr) ?: run {
            val (tag, level) = if (isInlineStdMember(mangled)) {
                "unresolved-symbol-inlined-std" to Level.DEBUG
            } else {
                "unresolved-symbol" to Level.WARN
            }
            log(tag, "no Function at $addr for $mangled", level, addr)
            return
        }

        // Re-parent + rename via Ghidra's demangler (reuses the GhidraClass leaf
        // ensureClassNamespace already created). Signature/calling-convention application stays
        // off (Demangler's defaults): the stab has richer types than the mangled name, and our
        // __thiscall choice below must win.
        if (!program.applyDemangling(addr, mangled)) {
            // Fall back to manual namespace + display-name handling.
            func.parentNamespace = ns
            val fallbackName = displayNameFor(mangled, className) ?: m.name
            if (func.name != fallbackName) func.setName(fallbackName, source)
            degradation(
                "method-demangle-fallback",
                "$className::${m.name}",
                "demangler did not apply to $mangled",
            )
        }

        // Mark __thiscall. The x86gcc cspec routes `this` as the first stack argument
        // (MSVC's x86win routes it via ECX); either way, accepted __thiscall + GhidraClass
        // namespace = Ghidra auto-injects hidden `this: Class*` at render time. Don't probe
        // func.getParameter(0)?.name to detect — for force-created functions the param list
        // isn't populated yet.
        val thiscallAccepted = runCatching { func.setCallingConvention("__thiscall") }
            .onFailure { warn("method-calling-convention", "$className::${m.name}: ${it.message}", func.entryPoint) }
            .isSuccess
        val ghidraInjectsThis = thiscallAccepted && func.parentNamespace is GhidraClass

        // gcc 3.x Method signatures: `[this, p1..pN, void_sentinel]`. FunctionT (free
        // functions) carries no inline params (they arrive via N_PSYM). Both adjustments
        // are Method-only. Walk Ref/InlineDef wrappers before pattern-matching.
        val (retDecl, paramDecls) = when (val sig = unwrapSignature(m.signature)) {
            is TypeDecl.Method -> sig.ret to if (ghidraInjectsThis) sig.params.drop(1) else sig.params
            is TypeDecl.FunctionT -> sig.ret to sig.params
            else -> return
        }

        typeRegistry.dataTypeFor(retDecl)?.let { ret ->
            func.setReturnType(ret, source)
        } ?: degradation(
            "method-ret-unresolved",
            "$className::${m.name}",
            retDecl.toString(),
        )

        // Always replace the formal-param list, falling back to Undefined4 for
        // unresolved types. Early-returning left Ghidra's auto-guessed signature in
        // place; combined with newly-applied __thiscall (which prepends its own `this`)
        // that produced double-`this` like `void Foo::Dump(Foo *this, ushort this, ...)`.
        val resolvedParams = paramDecls.map { typeRegistry.dataTypeFor(it) }
        for ((decl, dt) in paramDecls.zip(resolvedParams)) {
            if (dt == null) {
                degradation(
                    "method-param-unresolved",
                    "$className::${m.name}",
                    decl.toString(),
                )
            }
        }

        // Drop the void sentinel — only on Method-shape signatures; check the
        // UNWRAPPED form (m.signature is typically a Ref/InlineDef wrapper).
        val paramTypes = if (unwrapSignature(m.signature) is TypeDecl.Method) {
            resolvedParams.dropLastWhile { it is VoidDataType }
        } else {
            resolvedParams
        }.map { if (it is VoidDataType) Undefined4DataType.dataType else it }

        // Build the full param list ourselves (explicit `this` prefix + formals) and use
        // DYNAMIC_STORAGE_ALL_PARAMS. DYNAMIC_STORAGE_FORMAL_PARAMS + __thiscall varies by
        // Ghidra version on whether it auto-prepends `this`, and would rename our `arg0`
        // to `this` when the storage analyser placed it in the canonical this-slot.
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
        // Preserve N_PSYM-derived names set in StabsImporter.passB — the only source-level
        // names we have. Index them by their own position, not func.parameters', which by now
        // also holds injected `this` and (for by-value struct returns) StructReturnAnalyzer's
        // `__return_storage_ptr__` — a fixed offset misaligns and stamps `this` onto formal 0.
        val priorNames = func.parameters
            .filterNot { it.isAutoParameter || it.name in HIDDEN_PARAM_NAMES }
            .map { it.name }
        val formals = paramTypes.mapIndexed { i, pdt ->
            ParameterImpl(
                priorNames.getOrNull(i) ?: "arg$i",
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
     * Map a ctor/dtor mangled name to its in-class display form
     * (`_ZN3FooC[123]E…` → `Foo`, `_ZN3FooD[012]E…` → `~Foo`). Itanium emits up to three
     * symbols per ctor/dtor — same source-level name; Ghidra disambiguates by address.
     * Returns null for non-ctor/dtor methods.
     */
    private fun displayNameFor(mangled: String, className: String): String? {
        val ctorRe = Regex("""C[123]E[a-zA-Z_0-9$]*$""")
        val dtorRe = Regex("""D[012]E[a-zA-Z_0-9$]*$""")
        ctorRe.containsMatchIn(mangled).let { if (it) return className }
        dtorRe.containsMatchIn(mangled).let { if (it) return "~$className" }
        return null
    }

    private fun CanonicalGroup.buildAndApplyVtable(ns: GhidraClass) {
        // Itanium 32-bit: derived vtable = base entries first (in declaration order), with
        // overridden slots replaced. Override matching uses method name only — sufficient
        // for non-overloaded virtuals in the Cygwin gcc 3.4.4 corpus.
        val virtuals = collectAllVirtuals()
        if (virtuals.isEmpty()) {
            debug("vtable-skipped", "class=$className reason=no-virtuals")
            return
        }

        while (vftable.numComponents > 0) vftable.delete(0)
        for (m in virtuals) vftable.add(buildVirtualSlotType(m), m.name, "virtual ${m.name}")

        val addr = resolveVtableAddress() ?: return
        val rttiAddr = resolver.resolve(Itanium.zti(className))
        val addressPoint = program.layVtable(addr, vftable, className, ns, rttiAddr)
        debug("vtable-applied", "class=$className", address = addressPoint)

        // Plate-comment each virtual. An unresolved mangled name here is expected for
        // pure virtuals (slot points at __cxa_pure_virtual, no symbol emitted) or
        // DLL-imported impls. Slot type was already typed from the signature.
        virtuals.forEachIndexed { i, m ->
            val mAddr = m.mangled?.let(resolver::resolve)
            if (mAddr != null) {
                val func = program.functionManager.getFunctionAt(mAddr)
                if (func != null) {
                    program.listing.setComment(
                        func.entryPoint,
                        CommentType.PLATE,
                        "virtual ${m.name}; ${className}_vftable offset ${vftable.getComponent(i).offset}",
                    )
                } else {
                    debug(
                        "vtable-virtual-no-function",
                        "no Function at $mAddr for virtual method ${m.name} in $className",
                    )
                }
            } else {
                debug(
                    "vtable-virtual-no-impl",
                    "virtual method '${m.name}' in $className has no resolvable implementation " +
                        "(pure virtual or DLL import); slot type still applied",
                )
            }
        }
    }

    /** Walk Ref/InlineDef wrappers to the underlying Method/FunctionT (gcc binds signatures to their own type id). */
    private fun unwrapSignature(sig: TypeDecl<GlobalTypeId>): TypeDecl<GlobalTypeId>? {
        var cur: TypeDecl<GlobalTypeId>? = sig
        while (cur != null) {
            cur = when (cur) {
                is TypeDecl.Method, is TypeDecl.FunctionT -> return cur
                is TypeDecl.Ref -> harvest.getType(cur.id)?.body
                is TypeDecl.InlineDef -> cur.body
                else -> return null
            }
        }
        return null
    }

    /**
     * Build the typed function-pointer slot for [m]: `Pointer→FunctionDefinition(<sig>)`.
     * Slot field and pointee FD share the method's name to satisfy the
     * `atLeastOneVtableStructApplied` regression invariant. `this` resolves to the
     * declaring class's pointer or void*; __thiscall is dropped on platforms that lack it.
     */
    private fun CanonicalGroup.buildVirtualSlotType(m: MethodDecl<GlobalTypeId>): PointerDataType {
        val unwrapped = unwrapSignature(m.signature)
        val method = unwrapped as? TypeDecl.Method<GlobalTypeId> ?: run {
            degradation(
                "vftable-slot-untyped",
                "$className::${m.name}",
                "signature did not unwrap to a method: unwrapped=${
                    unwrapped?.let {
                        it::class.simpleName
                    } ?: "null"
                } " +
                    "sig=${m.signature}",
            )
            return PointerDataType(Undefined4DataType.dataType, dtm)
        }
        val funcDef = typeRegistry.buildFunctionDefinition(
            category = vftableCategory,
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

    /** Resolve _ZTV<class> address: try AddressResolver candidates, then symbol-table scan, then .rdata scan. */
    private fun CanonicalGroup.resolveVtableAddress(): Address? {
        val candidates = Itanium.ztvCandidates(className)
        candidates.firstNotNullOfOrNull { resolver.resolve(it) }?.let { return it }

        try {
            symtab.symbolIterator.firstOrNull {
                Itanium.decodesToClass(it.name, className)
            }?.let { return it.address }
        } catch (e: IllegalArgumentException) {
            warn("vtable-symbol-scan-error", "exception scanning symbol table for $className: ${e.message}")
        }

        val rdataBlock = program.memory.getBlock(".rdata")
        if (rdataBlock != null) {
            try {
                symtab.getSymbolIterator(rdataBlock.start, true)
                    .asIterable()
                    .takeWhile { it.address < rdataBlock.end }
                    .firstOrNull { Itanium.decodesToClass(it.name, className) }
                    ?.let { return it.address }
            } catch (e: IllegalArgumentException) {
                warn("vtable-rdata-scan-error", "exception scanning .rdata for $className: ${e.message}")
            }
        }

        val failureBucket = when {
            classBody.hasVTablePointerMarker && classBody.methods.none { it.virt == VirtKind.VIRTUAL } ->
                "no-virtual-methods-flagged-but-marker-set"

            else -> "truly-missing"
        }
        debug("vtable-failed", "class=$className reason=$failureBucket")
        degradation("vtable-failed", className, failureBucket)
        debug(
            "vtable-failed-$failureBucket",
            "class '$className': vtable not found (tried ${candidates.joinToString()})",
        )

        return null
    }

    private fun CanonicalGroup.collectAllVirtuals() = Virtuals(typeResolver).process(classBody)
}
