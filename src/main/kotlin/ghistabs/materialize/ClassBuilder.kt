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

/** Polymorphic-base detection, extracted for pure unit testing. */
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
        // Prefer the materialised AST at this id (real Struct body) — inline body is often a forward XRef.
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
     * Build/upgrade the class namespace from the demangled namespace chain of any mangled method
     * symbol; fall back to depth-aware splitting of the C++ source-form name.
     */
    private fun ensureClassNamespace(name: String, body: TypeDecl.Struct<GlobalTypeId>): GhidraClass {
        val parts = body.methods.firstNotNullOfOrNull { it.mangled }
            ?.let { namespaceChainFromMangled(it) }
            ?: QualifiedName.split(name)
        return buildNamespaceChain(parts.filter { it.isNotEmpty() })
    }

    /** Demangle and return the parent-namespace chain root-first (leaf is enclosing class). */
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
     * Get-or-create `<Class>_vftable` (the function-pointer-array struct) and return a Pointer to it.
     * Lives under `/ClassDataTypes/<Class>/` so `RecoveredClassHelper` and shift-S round-trip find it.
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
            // Trivial implicit special members appear in every class's stab but the compiler emits
            // no symbol for them — bucket separately so unresolved-symbol surfaces real problems.
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

        // Re-parent via demangler; disable sig/cspec/disasm application since the stab is richer.
        val demangleOpts = DemanglerOptions().apply {
            setApplySignature(false)
            setApplyCallingConvention(false)
            setDoDisassembly(false)
        }
        val demangleCmd = DemanglerCmd(addr, mangled, demangleOpts)
        if (!demangleCmd.applyTo(program)) {
            func.parentNamespace = ns
            val fallbackName = displayNameFor(mangled, className) ?: m.name
            if (func.name != fallbackName) func.setName(fallbackName, source)
            ctx.diagnostics.recordDegradation(
                "method-demangle-fallback",
                "$className::${m.name}",
                demangleCmd.statusMsg,
            )
        }

        // Ghidra injects implicit `this` iff thiscall is accepted by the cspec AND parent ns is a class.
        val thiscallAccepted = runCatching { func.setCallingConvention("__thiscall") }
            .onFailure { log("method-calling-convention", "$className::${m.name}: ${it.message}") }
            .isSuccess
        val ghidraInjectsThis = thiscallAccepted && func.parentNamespace is GhidraClass

        // gcc 3.x `#`-form methods carry `[this, p1, ..., pN, void_sentinel]`; FunctionT carries none.
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

        val resolvedParams = paramDecls.map { typeRegistry.dataTypeFor(it) }
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
        // Build the param list explicitly via DYNAMIC_STORAGE_ALL_PARAMS — DYNAMIC_STORAGE_FORMAL_PARAMS
        // + __thiscall renames arg0 to `this` and yields a duplicate.
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
        // Keep N_PSYM names that StabsImporter.passB set.
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

    /** `_ZN3FooC[123]E…` → `"Foo"`, `_ZN3FooD[012]E…` → `"~Foo"`; null otherwise. */
    private fun displayNameFor(mangled: String, className: String): String? {
        val ctorRe = Regex("""C[123]E[a-zA-Z_0-9$]*$""")
        val dtorRe = Regex("""D[012]E[a-zA-Z_0-9$]*$""")
        ctorRe.containsMatchIn(mangled).let { if (it) return className }
        dtorRe.containsMatchIn(mangled).let { if (it) return "~$className" }
        return null
    }

    /**
     * Build `<Class>_vftable` (array of `Pointer→FunctionDefinition`s, one per virtual slot) and
     * `<Class>_vtable` (Itanium prefix + embedded vftable), then apply the vtable at `_ZTV<class>`.
     * Inherited virtuals come first in declaration-order; overrides match by name (single-inheritance only).
     */
    private fun buildAndApplyVtable(
        className: String,
        body: TypeDecl.Struct<GlobalTypeId>,
        ns: GhidraClass,
        category: CategoryPath,
        structDt: Structure,
    ) {
        val inherited = collectInheritedVirtuals(body)
        val ownVirtuals = body.methods
            .filter { it.virt == VirtKind.VIRTUAL }
            .sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
        val virtuals = mergeVtableSlots(inherited, ownVirtuals)
        if (virtuals.isEmpty()) {
            ctx.diagnostics.recordVtable(className, "skipped", reason = "no-virtuals")
            return
        }

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
        // RecoveredClassHelper / shift-S require a symbol named "vftable" at the address.
        runCatching { symtab.createLabel(addr, "vftable", ns, source) }
            .onFailure { log("vftable-label-failed", "$className at $addr: ${it.message}") }
        log("vtable", "applied $vtableName", address = addr)
        ctx.diagnostics.recordVtable(className, "applied")

        // Plate-comment each virtual method at its function entry. First slot sits past the prefix.
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

    /** Class-scoped FunctionDefinition for [m], wrapped in a Pointer. `this` is void* when unresolvable. */
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
     * Try (1) [resolver] on each candidate, (2) symbol-table scan for `_ZTV*` decoding to [className],
     * (3) `.rdata` symbol scan. Returns null after bucketing the failure.
     */
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
