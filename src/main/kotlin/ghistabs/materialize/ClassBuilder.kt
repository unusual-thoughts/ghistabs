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
import ghistabs.harvest.CanonicalGroup
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.namespaceChain
import ghistabs.parse.*

/** Polymorphic-base detection helpers (extracted for pure unit testing). */
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

        // Prefer the ast at this id (real struct body) over the inline body, which is
        // often a forward XRef. Without the fallback, polymorphism detection misses
        // inherited vfptrs (e.g. bouniaf → InlineDef(ExprInst id, XRef body)).
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

    /** Materialise class struct + namespace + (optional) vtable struct, apply at _ZTV. */
    fun build(group: CanonicalGroup) {
        val name = group.key.name
        val category = group.key.category
        val body = group.ast.body as TypeDecl.Struct<GlobalTypeId>
        val structDt = typeRegistry.dataTypeFor(group.ast.id)
        if (structDt !is Structure) {
            log("class-not-struct", "skipping ${structDt?.let { it::class.simpleName }} class '$name' at $category ")
            return
        }

        val isPoly = body.hasVTablePointerMarker ||
            body.methods.any { it.virt == VirtKind.VIRTUAL } ||
            body.fields.any {
                it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr"
            }
        if (isPoly) ensureVfptrFirstField(structDt, body, name, category)

        val ns = ensureClassNamespace(name, body)
        for (m in body.methods) reparentMethod(m, name, ns, structDt)
        if (isPoly) buildAndApplyVtable(name, body, ns, category, structDt)
    }

    /**
     * Derive the class's namespace chain. Prefers demangling a method's Itanium symbol
     * (handles templates) over splitting the source-form name (handles classes with no
     * methods or unmangleable symbols).
     */
    private fun ensureClassNamespace(name: String, body: TypeDecl.Struct<GlobalTypeId>): GhidraClass {
        val parts = body.methods.firstNotNullOfOrNull { it.mangled }
            ?.let { namespaceChain(program, it) }
            ?: splitQualified(name)
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

    private fun ensureVfptrFirstField(
        structDt: Structure,
        body: TypeDecl.Struct<GlobalTypeId>,
        className: String,
        category: CategoryPath,
    ) {
        val vfptrName = ClassUtils.VFPTR
        val parserVptrOffset = body.fields
            .firstOrNull {
                it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr"
            }?.let { (it.offsetBits / 8).toInt() }

        val targetOffset = parserVptrOffset ?: 0
        val existingComp = runCatching { structDt.getComponentAt(targetOffset) }.getOrNull()
        val snapshot = existingComp?.let {
            FirstComponentSnapshot(
                fieldName = it.fieldName,
                offsetBytes = it.offset,
                isUndefined = it.dataType is Undefined1DataType,
            )
        }

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
     * {vfptr} points at the function-pointer array inside the vtable record
     * (`_ZTV<class> + 2*ptrSize`), not at the record start. Modelled as `<Class>_vftable*`
     * under `/ClassDataTypes/<Class>/` so `RecoveredClassHelper` / shift-S round-trip
     * can find it.
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
            // Trivial implicit special members (default ctor, copy/move ctor/assignment, dtor)
            // appear in every class's stab list but get no emitted symbol. Bucket separately
            // so the unresolved-symbol log surfaces real problems.
            if (isImplicitTrivialSpecialMember(mangled)) {
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

        // Re-parent + rename via Ghidra's demangler (reuses the GhidraClass leaf
        // ensureClassNamespace already created). Signature/calling-convention application stays
        // off (Demangler's defaults): the stab has richer types than the mangled name, and our
        // __thiscall choice below must win.
        if (!applyDemangling(program, addr, mangled)) {
            // Fall back to manual namespace + display-name handling.
            func.parentNamespace = ns
            val fallbackName = displayNameFor(mangled, className) ?: m.name
            if (func.name != fallbackName) func.setName(fallbackName, source)
            ctx.diagnostics.recordDegradation(
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
            .onFailure { log("method-calling-convention", "$className::${m.name}: ${it.message}") }
            .isSuccess
        val ghidraInjectsThis = thiscallAccepted && func.parentNamespace is GhidraClass

        // gcc 3.x Method signatures: `[this, p1..pN, void_sentinel]`. FunctionT (free
        // functions) carries no inline params (they arrive via N_PSYM). Both adjustments
        // are Method-only. Walk Ref/InlineDef wrappers before pattern-matching.
        val retDecl: TypeDecl<GlobalTypeId>
        val paramDecls: List<TypeDecl<GlobalTypeId>>
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

        // Always replace the formal-param list, falling back to Undefined4 for
        // unresolved types. Early-returning left Ghidra's auto-guessed signature in
        // place; combined with newly-applied __thiscall (which prepends its own `this`)
        // that produced double-`this` like `void Foo::Dump(Foo *this, ushort this, ...)`.
        val resolvedParams = paramDecls.map { typeRegistry.dataTypeFor(it) }
        // Drop the void sentinel — only on Method-shape signatures; check the
        // UNWRAPPED form (m.signature is typically a Ref/InlineDef wrapper).
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
        // Preserve N_PSYM-derived names set in StabsImporter.passB — those are
        // the only source-level names we have. When Ghidra injects `this` at slot 0,
        // user params start at index 1 in func.parameters.
        val priorOffset = if (ghidraInjectsThis) 1 else 0
        val formals = paramTypes.mapIndexed { i, pdt ->
            ParameterImpl(
                func.parameters.getOrNull(i + priorOffset)?.name ?: "arg$i",
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

    private fun buildAndApplyVtable(
        className: String,
        body: TypeDecl.Struct<GlobalTypeId>,
        ns: GhidraClass,
        category: CategoryPath,
        structDt: Structure,
    ) {
        // Itanium 32-bit: derived vtable = base entries first (in declaration order), with
        // overridden slots replaced. Override matching uses method name only — sufficient
        // for non-overloaded virtuals in the Cygwin gcc 3.4.4 corpus.
        val inherited = collectInheritedVirtuals(body)
        val ownVirtuals = body.methods
            .filter { it.virt == VirtKind.VIRTUAL }
            .sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
        val virtuals = mergeVtableSlots(inherited, ownVirtuals)
        if (virtuals.isEmpty()) {
            ctx.diagnostics.recordVtable(className, "skipped", reason = "no-virtuals")
            return
        }

        // Two related structs under /ClassDataTypes/<Class>/:
        //   <Class>_vftable — function-pointer array (what {vfptr} points at). Each slot is
        //                     Pointer→FunctionDefinition(<sig>) so the decompiler resolves
        //                     virtual calls; matches RecoveredClassHelper for shift-S round-trip.
        //   <Class>_vtable  — full record at _ZTV: offset_to_top + rtti + embedded vftable.
        val classDataTypesRoot = CategoryPath(CategoryPath.ROOT, "ClassDataTypes")
        val vftableCategory = CategoryPath(classDataTypesRoot, className)
        val vftableName = "${className}_vftable"
        val vtableName = "${className}_vtable"
        val ptrSize = program.defaultPointerSize

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

        val candidates = VtableSymbolCandidates.mangledZtvCandidates(className)
        if ('<' in className) {
            log("vtable-templated-skip", "class '$className' has template args; _ZTV lookup unsupported in v1")
        }
        val addr = resolveVtableAddress(className, body, candidates) ?: return

        program.listing.clearCodeUnits(addr, addr.add(vtable.length.toLong() - 1), false)
        program.listing.createData(addr, vtable)
        // RecoveredClassHelper / shift-S require a symbol containing "vftable" at the
        // Data address. The demangler emits `<class>::vtable` (no f); this label is
        // what makes us discoverable.
        runCatching { symtab.createLabel(addr, "vftable", ns, source) }
            .onFailure { log("vftable-label-failed", "$className at $addr: ${it.message}") }
        log("vtable", "applied $vtableName", address = addr)
        ctx.diagnostics.recordVtable(className, "applied")

        // Plate-comment each virtual. An unresolved mangled name here is expected for
        // pure virtuals (slot points at __cxa_pure_virtual, no symbol emitted) or
        // DLL-imported impls. Slot type was already typed from the signature.
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

    /** Walk Ref/InlineDef wrappers to the underlying Method/FunctionT (gcc binds signatures to their own type id). */
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
     * Build the typed function-pointer slot for [m]: `Pointer→FunctionDefinition(<sig>)`.
     * Slot field and pointee FD share the method's name to satisfy the
     * `atLeastOneVtableStructApplied` regression invariant. `this` resolves to the
     * declaring class's pointer or void*; __thiscall is dropped on platforms that lack it.
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

    /** Resolve _ZTV<class> address: try AddressResolver candidates, then symbol-table scan, then .rdata scan. */
    private fun resolveVtableAddress(
        className: String,
        body: TypeDecl.Struct<GlobalTypeId>,
        candidates: List<String>,
    ): Address? {
        candidates.firstNotNullOfOrNull { resolver.resolve(it) }?.let { return it }

        try {
            symtab.symbolIterator.firstOrNull {
                (it.name.startsWith("_ZTV") || it.name.startsWith("__ZTV")) &&
                    VtableSymbolCandidates.decodesToClass(program, it.name, className)
            }?.let { return it.address }
        } catch (e: IllegalArgumentException) {
            log("vtable-symbol-scan-error", "exception scanning symbol table for $className: ${e.message}")
        }

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
     * Gather virtuals from the full inheritance chain (bouniaf → ExprInst → bouniaf → Inst:
     * Inst::GetOffset belongs in bouniaf's vtable but isn't in ExprInst's direct methods).
     * Override matching is by name only — fine for non-overloaded virtuals.
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
            // Depth-first: grand-base virtuals precede direct-base's own additions,
            // matching their slot order in the derived vtable.
            gatherTransitive(baseStruct, out, visited)
            for (m in baseStruct.methods.filter { it.virt == VirtKind.VIRTUAL }) {
                val idx = out.indexOfFirst { it.name == m.name }
                if (idx >= 0) out[idx] = m else out += m
            }
        }
    }

    /** Apply derived overrides on inherited slots (match by name). */
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

    /** Lowest-offset polymorphic base, or null. Determines whether to insert a vfptr or inherit. */
    internal fun firstPolymorphicBase(body: TypeDecl.Struct<GlobalTypeId>): BaseDecl<GlobalTypeId>? =
        ClassBuilderHelpers(typeResolver).firstPolymorphicBase(body)

    internal fun hasPolymorphicBaseSubobject(body: TypeDecl.Struct<GlobalTypeId>): Boolean =
        ClassBuilderHelpers(typeResolver).hasPolymorphicBaseSubobject(body)
}
