package ghistabs.materialize

import ghidra.app.util.NamespaceUtils
import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.Demangler
import ghistabs.applyDemangling
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.LocatedType
import ghistabs.harvest.demangledClassPath
import ghistabs.importer.ImportContext
import ghistabs.isInjected
import ghistabs.isMethod
import ghistabs.materialize.itanium.*
import ghistabs.materialize.itanium.Itanium.isImplicitTrivialSpecialMember
import ghistabs.materialize.itanium.Itanium.isInlineStdMember
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Struct.Method

class ClassBuilder(
    private val registry: DataTypeRegistry,
    private val index: HarvestIndex,
    private val ctx: ImportContext<*>,
) : DiagnosticSink by ctx {
    private val program = ctx.program
    private val resolver = ctx.resolver
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

    companion object {
        private val source = SourceType.IMPORTED

        fun LocatedType.isClass() = type.body is TypeDecl.Struct &&
            (
                type.body.methods.isNotEmpty() ||
                    type.body.hasVTablePointerMarker ||
                    // gcc 12 emits the vfptr as a regular `_vptr.XX` field instead of the
                    // `~%<id>;` marker hasVTablePointerMarker watches for — without this check
                    // every polymorphic class in xmltest would be skipped.
                    type.body.fields.any { Itanium.isVptrField(it.name) }
                )

        private val LocatedType.classBody get() = type.body as TypeDecl.Struct<GlobalTypeId>
        private val LocatedType.className get() = location.name

        // <Class>_vftable under /ClassDataTypes/<Class>/ — the function-pointer array {vfptr}
        // points at, laid at the vtable's address point (_ZTV + 2*ptrSize). Each slot is
        // Pointer→FunctionDefinition(<sig>) so the decompiler resolves virtual calls and
        // RecoveredClassHelper / shift-S round-trip. The offset_to_top + rtti header words sit
        // before the address point as plain Data (no enclosing struct — see buildAndApplyVtable).
        private val LocatedType.vftableCategory get() = CategoryPath(Itanium.classDataTypesRoot, className)
        private val LocatedType.vftableName get() = "${className}_vftable"
    }

    private val LocatedType.vftable
        get() = registry.getOrRegister<Structure>(vftableCategory, vftableName) {
            StructureDataType(vftableCategory, vftableName, 0, dtm)
        }

    // Fully-qualified C++ name (`std::basic_ostream<char,…>`), for matching a demangled `_ZTV`
    // symbol's namespace chain. `className` (key.name) is only the leaf now that byCanonicalKey
    // files the scope into the category, so it can't match the demangler's full chain. Recover the
    // chain from a method-bearing member's mangled name — the exact form GnuDemangler emits.
    private val LocatedType.qualifiedClassName: String
        get() = (sequenceOf(type) + members.mapNotNull { index.byId(it) })
            .firstNotNullOfOrNull { it.demangledClassPath() }?.joinToString("::") ?: className

    /**
     * {vfptr} points at the function-pointer array at the vtable's address point
     * (`_ZTV<class> + 2*ptrSize`), not at the record start. Modelled as `<Class>_vftable*`
     * under `/ClassDataTypes/<Class>/` so `RecoveredClassHelper` / shift-S round-trip
     * can find it.
     */
    private fun LocatedType.ensureVtableTypeAndPointer(): Pointer = PointerDataType.getPointer(vftable, dtm)

    /**
     * Build every class/vtable group once. Each class header included by N CUs produces N TypeAsts
     * with distinct ids but identical ghidraName (one PE fixture: 86 names duplicated up to 11x);
     * materializeAll already collapsed by name, and iterating canonical groups builds each class
     * once, off the most-detailed body. Returns the number of classes built.
     */
    fun buildAll(): Int {
        val classes = index.byLocation.values.filter { it.isClass() }
        ctx.monitor.initialize(classes.size.toLong(), "Stabs: building classes")
        var built = 0
        for (group in classes) {
            ctx.monitor.increment()
            try {
                group.build()
                built++
            } catch (t: Throwable) {
                err("class-apply-error", "${group.location}: ${t.message}")
            }
        }
        sweepUnclaimedVtables()
        return built
    }

    /** Materialize class struct + namespace + (optional) vtable struct, apply at _ZTV. */
    fun LocatedType.build() {
        val category = location.category
        val structDt = registry.dataTypeFor(type.id)
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
            index.hasPolymorphicBaseSubobject(classBody)
        if (isPoly) ensureVfptrFirstField(structDt)

        val ns = ensureClassNamespace()
        for (m in classBody.methods) reparentMethod(m, ns, structDt)
        if (isPoly) buildAndApplyVtable(ns)
    }

    /**
     * Derive the class's namespace chain by demangling any Itanium symbol the class owns (handles
     * templates), falling back to the source-form name, which carries only the leaf. A static
     * member's linkage name serves as well as a method's, and is all a pure-constants class like
     * `std::ctype_base` has — without it those land at the root instead of under `std`.
     */
    private fun LocatedType.ensureClassNamespace(): GhidraClass {
        val parts = (
            classBody.methods.firstNotNullOfOrNull { it.mangled }
                ?: classBody.fields.firstNotNullOfOrNull { it.mangled }
            )?.let { Demangler.namespaces(it) }
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

    private fun LocatedType.ensureVfptrFirstField(structDt: Structure) {
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
            hasPolymorphicBaseSubobject = index.hasPolymorphicBaseSubobject(classBody),
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

            is VfptrAction.CollisionAt -> degradation(
                "vfptr-collision",
                className,
                "cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})",
            )
        }
    }

    private fun LocatedType.reparentMethod(m: Method<GlobalTypeId>, ns: GhidraClass, structDt: Structure) {
        val mangled = m.mangled ?: run {
            degradation("method-no-mangled", "$className::${m.name}", "stab has no mangled symbol")
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
            val fallbackName = Itanium.specialMemberDisplayName(mangled, className) ?: m.name
            if (func.name != fallbackName) func.setName(fallbackName, source)
            degradation(
                "method-demangle-fallback",
                "$className::${m.name}",
                "demangler did not apply to $mangled",
                func.entryPoint,
            )
        }

        // gcc 3.x Method signatures: `[this, p1..pN, void_sentinel]`. FunctionT carries no inline
        // params — free functions and `?`-flagged statics alike get theirs from N_PSYM. Walk
        // Ref/InlineDef wrappers before pattern-matching.
        val sig = unwrapSignature(m.signature)
        val retDecl = when (sig) {
            is TypeDecl.Method -> sig.ret
            is TypeDecl.FunctionT -> sig.ret
            else -> return degradation(
                "method-signature-unwrap-failed",
                "$className::${m.name}",
                "${m.signature}",
                func.entryPoint,
            )
        }

        registry.resolveRef(retDecl)?.let { func.setReturnType(it, source) }
            ?: degradation(
                "method-ret-unresolved",
                "$className::${m.name}",
                retDecl.toString(),
                func.entryPoint,
            )

        // A static member takes no `this`, so it keeps the default convention and the params
        // applyAllFunctions already read off its N_PSYMs. Falling through forced __thiscall
        // (a phantom `FileSystemImage *this`) and then replaced the real params with the empty
        // list its `f(ret)` signature carries. Returning is not enough: Itanium mangling cannot
        // distinguish a static member from an instance one, so Ghidra's own demangler pass already
        // gave it __thiscall, and Ghidra auto-injects `this` for any this-bearing convention on a
        // GhidraClass member. The stabs `?` flag is the only thing that knows better.
        if (m.virt == VirtKind.STATIC) {
            debug("method-static-no-this")
            if (func.callingConvention?.hasThisPointer() == true) {
                runCatching {
                    func.setCallingConvention(program.compilerSpec.defaultCallingConvention.name)
                }.onFailure {
                    degradation("method-calling-convention", "$className::${m.name}", it.message, func.entryPoint)
                }
            }
            return
        }

        // Mark __thiscall. The x86gcc cspec routes `this` as the first stack argument
        // (MSVC's x86win routes it via ECX); either way, accepted __thiscall + GhidraClass
        // namespace = Ghidra auto-injects hidden `this: Class*` at render time. Don't probe
        // func.getParameter(0)?.name to detect — for force-created functions the param list
        // isn't populated yet.
        val thiscallAccepted = runCatching { func.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall) }
            .onFailure {
                degradation("method-calling-convention", "$className::${m.name}", it.message, func.entryPoint)
            }
            .isSuccess
        val ghidraInjectsThis = thiscallAccepted && func.isMethod

        val paramDecls = when (sig) {
            is TypeDecl.Method -> if (ghidraInjectsThis) sig.params.drop(1) else sig.params
            is TypeDecl.FunctionT -> sig.params
        }

        // Always replace the formal-param list, falling back to Undefined4 for
        // unresolved types. Early-returning left Ghidra's auto-guessed signature in
        // place; combined with newly-applied __thiscall (which prepends its own `this`)
        // that produced double-`this` like `void Foo::Dump(Foo *this, ushort this, ...)`.
        val resolvedParams = paramDecls.map { registry.resolveRef(it) }
        for ((decl, dt) in paramDecls.zip(resolvedParams)) {
            if (dt == null) {
                degradation(
                    "method-param-unresolved",
                    "$className::${m.name}",
                    decl.toString(),
                    func.entryPoint,
                )
            }
        }

        // Drop the void sentinel — only on Method-shape signatures.
        val paramTypes = if (sig is TypeDecl.Method) {
            resolvedParams.dropLastWhile { it is VoidDataType }
        } else {
            resolvedParams
        }.mapIndexed { i, dt ->
            if (dt is VoidDataType) {
                degradation(
                    "method-param-void",
                    "$className::${m.name}",
                    "void at [$i]; substituted Undefined4 to keep arity",
                    func.entryPoint,
                )
                Undefined4DataType.dataType
            } else {
                dt
            }
        }

        // Explicit `this` + formals, under DYNAMIC_STORAGE_ALL_PARAMS: FORMAL_PARAMS + __thiscall
        // varies by Ghidra version on whether it auto-prepends `this`, and would rename our `arg0`
        // to `this` when the storage analyzer placed it in the canonical this-slot.
        // The parameter is then stripped and re-derived from the DTM's class structure, not from
        // [classPtr] — but passing it is what keeps ALL_PARAMS from taking a formal for an
        // "inferred unnamed this".
        val classPtr = PointerDataType(structDt, dtm)
        val explicitThis = if (ghidraInjectsThis) {
            listOf(
                ParameterImpl(
                    Function.THIS_PARAM_NAME,
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
            .filterNot { it.isInjected }
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

    private fun LocatedType.buildAndApplyVtable(ns: GhidraClass) {
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
        claimedVtables += addr
        val shape = program.vtableShape(addr, resolver)

        // One vbase offset per virtual base, so the two counts must agree. They are derived
        // independently — the stab's base graph vs. where vtableShape put offset_to_top — which makes
        // a disagreement the one cheap check that the address point was located correctly.
        val virtualBases = index.virtualBases(classBody)
            .map { registry.resolveRef(it.type)?.name ?: "<unresolved base>" }
        if (shape.prefix.size < virtualBases.size) {
            degradation(
                "vtable-vbase-count-mismatch",
                className,
                "${shape.prefix.size} prefix word(s) before offset_to_top, " +
                    "${virtualBases.size} virtual base(s) declared",
            )
        }

        val addressPoint = program.layVtable(shape, vftable, className, ns, resolver, virtualBases)
        debug("vtable-applied", "class=$className", address = addressPoint)
        laySecondaryVtables(shape, className, ns)

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
                        "virtual method ${m.name} in $className not found",
                        mAddr,
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
    private fun unwrapSignature(sig: GlobalTypeDecl) =
        index.resolveWith(sig) { it.takeIf { d -> d is TypeDecl.Method || d is TypeDecl.FunctionT } }

    /**
     * Build the typed function-pointer slot for [m]: `Pointer→FunctionDefinition(<sig>)`.
     * Slot field and pointee FD share the method's name to satisfy the
     * `atLeastOneVtableStructApplied` regression invariant. `this` resolves to the
     * declaring class's pointer or void*; __thiscall is dropped on platforms that lack it.
     */
    private fun LocatedType.buildVirtualSlotType(m: Method<GlobalTypeId>): PointerDataType {
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
        val funcDef = registry.buildFunctionDefinition(
            category = vftableCategory,
            name = m.name,
            ret = method.ret,
            params = method.params,
            thisType = registry.resolveRef(method.cls) ?: PointerDataType(VoidDataType(), dtm).also {
                degradation("vftable-slot-this-untyped", "$className::${m.name}", "${method.cls}; used void*")
            },
            callingConvention = CompilerSpec.CALLING_CONVENTION_thiscall,
            at = "$className::${m.name}",
        )
        val resolved = registry.register(funcDef) as FunctionDefinition
        return PointerDataType(resolved, dtm)
    }

    /** Vtable records a harvested class claimed, so [sweepUnclaimedVtables] can tell what is left. */
    private val claimedVtables = mutableSetOf<Address>()

    /**
     * Lay every `_ZTV…` symbol no harvested class claimed. `buildAndApplyVtable` runs per group, i.e.
     * only for a class we have a `T`-stab body for; libsupc++ and libstdc++ link without stabs, so
     * their polymorphic classes (`__cxxabiv1::__si_class_type_info`, `std::basic_filebuf<char,…>`)
     * own a real vtable that nothing ever visits — 53 of unbouniaf's 58 `_ZTV` symbols.
     *
     * Lossy by nature: with no method list the slots can only be named and typed from whatever sits
     * at the addresses they point to, and the array's length is inferred (see [vtableSlotTargets]).
     * The class struct is *not* synthesised — this is the vtable level only; §24 covers the same
     * classes at the typeinfo-record level.
     */
    private fun sweepUnclaimedVtables() {
        val unclaimed = symtab.symbolIterator
            .filter { it.address !in claimedVtables }
            .mapNotNull { sym -> Itanium.vtableClassOf(sym.name)?.let { sym.address to it } }
            .distinctBy { (addr, _) -> addr }
            .toList()

        ctx.monitor.initialize(unclaimed.size.toLong(), "Stabs: sweeping unclaimed vtables")
        for ((addr, qualified) in unclaimed) {
            ctx.monitor.increment()
            val shape = program.vtableShape(addr, resolver)
            val targets = program.vtableSlotTargets(shape.addressPoint, resolver)
            if (targets.isEmpty()) {
                degradation("vtable-swept-empty", qualified, "no function pointers", shape.addressPoint)
                continue
            }
            val leaf = canonTemplateName(splitQualified(qualified).last())
            val category = CategoryPath(Itanium.classDataTypesRoot, leaf)
            val vftable = registry.getOrRegister<Structure>(category, "${leaf}_vftable") {
                StructureDataType(category, "${leaf}_vftable", 0, dtm)
            }
            // A class whose own group failed to resolve its vtable left its stab-typed slots here;
            // those beat anything read back off the target addresses.
            if (vftable.numComponents == 0) {
                val used = mutableSetOf<String>()
                for (target in targets) vftable.addSweptSlot(category, target, used)
            }

            val ns = buildNamespaceChain(splitQualified(qualified))
            val addressPoint = program.layVtable(shape, vftable, qualified, ns, resolver)
            debug("vtable-reconstructed", "${targets.size} slot(s) typed from targets", addressPoint, qualified)
            laySecondaryVtables(shape, leaf, ns)
        }
    }

    /**
     * Lay the sub-vtables that follow the primary record [primary] (§54). Slots are typed off their
     * targets like a swept table's: a secondary holds `_ZTv0_n…`/`_ZThn…` thunks, which are their own
     * symbols with their own names.
     *
     * Where the primary ends is read off memory, not off the vftable laid there — `CryptoPP::Base`
     * declares fewer virtuals than its table holds, which put the walk inside the function array.
     * Each sub-vtable gets its own `internal_<i>` category, or a thunk sharing its target's leaf name
     * forks a `.conflict` per slot (1874 on crypto_mi).
     */
    private fun laySecondaryVtables(primary: VtableShape, leaf: String, ns: Namespace) {
        val rtti = program.readWord(primary.rttiHeader) ?: return
        val ptr = program.defaultPointerSize.toLong()
        val slots = program.vtableSlotTargets(primary.addressPoint, resolver).size
        val subs = program.secondaryVtables(primary.addressPoint.add(slots * ptr), rtti, resolver)
        subs.forEachIndexed { i, sub ->
            val category = CategoryPath(CategoryPath(Itanium.classDataTypesRoot, leaf), "internal_$i")
            val name = "${leaf}_vftable_internal_$i"
            val vftable = registry.getOrRegister<Structure>(category, name) {
                StructureDataType(category, name, 0, dtm)
            }
            if (vftable.numComponents == 0) {
                val used = mutableSetOf<String>()
                for (target in sub.targets) vftable.addSweptSlot(category, target, used)
            }
            val at = program.layVtable(sub.shape, vftable, leaf, ns, resolver, label = Itanium.INTERNAL_VFTABLE)
            debug("vtable-secondary", "class=$leaf index=$i slots=${sub.targets.size}", address = at)
        }
    }

    /**
     * Add the swept slot pointing at [target]. Always `Pointer→FunctionDefinition`, never a bare
     * `void*`: an abstract class's slots point at `__cxa_pure_virtual`, a real function that honestly
     * has no signature to recover, and a `void*` there reads as a failure to type it.
     *
     * One name serves as both the field name and the definition's — `atLeastOneVtableStructApplied`
     * requires they agree (RecoveredClassHelper / shift-S round-trip) — so it has to be unique in the
     * category too: `std::num_get` has six `do_get` overloads and `std::ctype` two of each `do_is`/
     * `do_widen`/…, and one name across all of them forks a `.conflict` per slot (32 on unbouniaf).
     * [used] carries the names already spent on this table.
     */
    private fun Structure.addSweptSlot(category: CategoryPath, target: Address, used: MutableSet<String>) {
        val linkage = symtab.getSymbols(target).map { it.name }.firstOrNull(Itanium::isProbablyMangled)
            ?: symtab.getPrimarySymbol(target)?.name
            ?: "slot"
        val leaf = Demangler.of(linkage)?.name ?: linkage
        val name = generateSequence(0) { it + 1 }
            .map { if (it == 0) leaf else "${leaf}_$it" }
            .first(used::add)

        val funcDef = program.functionManager.getFunctionAt(target)
            ?.let { FunctionDefinitionDataType(category, name, it.signature, dtm) }
            ?: demangledDefinition(category, name, linkage)
        add(PointerDataType(registry.register(funcDef), dtm), name, "$target")
    }

    /** FunctionDefinition [name] carrying what [linkage] declares — the only type source for a slot
     *  target that has a linkage name and nothing else. Names but does not type an unmangled one. */
    private fun demangledDefinition(category: CategoryPath, name: String, linkage: String) =
        FunctionDefinitionDataType(category, name, dtm).apply {
            fun DemangledDataType.dt() = runCatching { getDataType(dtm) }.getOrNull()
                ?: Undefined4DataType.dataType.also {
                    degradation("vftable-demangled-untyped", "$category/$name", "demangler gave no type for $this")
                }
            (Demangler.of(linkage) as? DemangledFunction)?.let { df ->
                df.returnType?.let { returnType = it.dt() }
                setArguments(
                    *df.parameters
                        .filterNot { it.type.isVoid && it.type.pointerLevels == 0 && !it.type.isReference }
                        .mapIndexed { i, p -> ParameterDefinitionImpl("arg$i", p.type.dt(), null) }
                        .toTypedArray(),
                )
            }
        }

    /** `_ZTV<class>` demangled qualified-class-name → address, built once. Replaces the per-class
     *  `O(classes × symbols)` demangle scan that made [resolveVtableAddress] pathological on CryptoPP
     *  (thousands of classes × thousands of symbols). First symbol per class wins (iteration order). */
    private val vtableAddressByClass: Map<String, Address> by lazy {
        buildMap {
            for (sym in symtab.symbolIterator) {
                Itanium.vtableClassOf(sym.name)?.let { putIfAbsent(it, sym.address) }
            }
        }
    }

    /** Resolve _ZTV<class> address: try AddressResolver candidates, then the demangled-vtable index. */
    private fun LocatedType.resolveVtableAddress(): Address? {
        val candidates = Itanium.ztvCandidates(className)
        candidates.firstNotNullOfOrNull { resolver.resolve(it) }?.let { return it }

        vtableAddressByClass[qualifiedClassName]?.let { return it }

        val failureBucket = when {
            classBody.hasVTablePointerMarker && classBody.methods.none { it.virt == VirtKind.VIRTUAL } ->
                "no-virtual-methods-flagged-but-marker-set"

            else -> "truly-missing"
        }
        degradation("vtable-failed", className, "$failureBucket (tried ${candidates.joinToString()})")
        debug(
            "vtable-failed-$failureBucket",
            "class '$className': vtable not found (tried ${candidates.joinToString()})",
        )

        return null
    }

    private fun LocatedType.collectAllVirtuals() = index.collectAllVirtuals(classBody)
}
