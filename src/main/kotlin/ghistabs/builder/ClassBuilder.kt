package ghistabs.builder

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.diag.BookmarkSink
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.parser.*

class ClassBuilder(
    private val program: Program,
    private val typeRegistry: TypeRegistry,
    private val resolver: AddressResolver,
    private val sink: BookmarkSink,
    /** All struct ASTs harvested in Pass A, indexed by name. */
    private val structAstsByName: Map<String, TypeDecl.Struct>,
    /** All type ASTs indexed by TypeId for inheritance resolution. */
    private val typeAstsById: Map<TypeId, TypeAst>? = null,
    private val ctx: ImportContext,
) {
    private val source = SourceType.IMPORTED
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

    /** Materialise a class struct + namespace + (optional) vtable struct + apply at _ZTV. */
    fun build(name: String, body: TypeDecl.Struct, category: CategoryPath) {
        // 1. Locate the materialised Structure in the DTM.
        // (typeRegistry.dataTypeFor does not handle TypeDecl.Struct — Structs are only
        // looked up by TypeId via materialiseAll; here we resolve by (category, name).)
        val structDt = (dtm.getDataType(category, name) as? Structure) ?: run {
            sink.log("class-not-struct", "skipping non-struct class '$name' at $category")
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
        val ns = ensureClassNamespace(name)

        // 4. Re-parent member functions.
        for (m in body.methods) reparentMethod(m, name, ns)

        // 5. If polymorphic: build <Class>_vtable struct + apply at _ZTV<class> address.
        if (isPoly) buildAndApplyVtable(name, body, ns, category, structDt)
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

            is VfptrAction.CollisionAt -> sink.log(
                "vfptr-collision",
                "$className: cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})",
            )
        }
    }

    private fun ensureVtableTypeAndPointer(className: String, category: CategoryPath) = PointerDataType.getPointer(
        dtm.getDataType(category, "${className}_vtable") ?: StructureDataType(
            category,
            "${className}_vtable",
            0,
            dtm,
        ).let { dtm.addDataType(it, DataTypeConflictHandler.KEEP_HANDLER) },
        dtm,
    )

    private fun reparentMethod(m: MethodDecl, className: String, ns: GhidraClass) {
        val mangled = m.mangled ?: run {
            sink.log("method-no-mangled", "$className::${m.name}: stab has no mangled symbol")
            return
        }
        val addr = resolver.resolve(mangled) ?: run {
            sink.log("unresolved-symbol", "method $mangled (in $className)")
            return
        }
        val func = program.functionManager.getFunctionAt(addr) ?: run {
            sink.log("unresolved-symbol", "no Function at $addr for $mangled")
            return
        }

        // 1. Re-parent.
        func.parentNamespace = ns

        // 2. Choose the in-class display name:
        val displayName = displayNameFor(mangled, className) ?: m.name
        if (func.name != displayName) func.setName(displayName, source)

        // 3. Apply prototype from MethodDecl.signature.
        val sig = m.signature
        if (sig is TypeDecl.FunctionT) {
            val ret = typeRegistry.dataTypeFor(sig.ret)
            if (ret != null) func.setReturnType(ret, source)

            // Only replace parameters if all types resolve to non-null. This prevents
            // overwriting better Phase 4 assignments.
            val paramTypes = sig.params.map { typeRegistry.dataTypeFor(it) }
            val allResolved = paramTypes.all { it != null }

            if (allResolved && paramTypes.isNotEmpty()) {
                val params = paramTypes.mapIndexed { i, pdt ->
                    ghidra.program.model.listing.ParameterImpl(
                        "arg$i",
                        pdt ?: Undefined4DataType.dataType,
                        program,
                        source,
                    )
                }
                func.replaceParameters(
                    params,
                    ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    true,
                    source,
                )
            } else if (paramTypes.any { it == null }) {
                sink.log(
                    "method-param-unresolved",
                    "$className::${m.name}: some parameter types unresolved; keeping Phase 4 assignment",
                )
            }
        }
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
        className: String,
        body: TypeDecl.Struct,
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

        // 2. Build / look up <Class>_vtable struct.
        val vtableName = "${className}_vtable"
        val ptrSize = program.defaultPointerSize // typically 4 on 32-bit
        val existing = dtm.getDataType(category, vtableName) as? Structure
        val vtable = existing ?: StructureDataType(category, vtableName, 0, dtm).also {
            dtm.addDataType(it, DataTypeConflictHandler.KEEP_HANDLER)
        }
        // Clear any old contents (idempotent re-import).
        while (vtable.numComponents > 0) vtable.delete(0)
        for (m in virtuals) {
            val fnDt = PointerDataType.getPointer(
                Undefined4DataType.dataType, // generic FN ptr
                dtm,
            )
            vtable.add(fnDt, ptrSize, m.name, "virtual ${m.name}")
        }

        // 3. Resolve _ZTV<class> address with fallbacks.
        val candidates = VtableSymbolCandidates.mangledZtvCandidates(className)

        // If class name contains template args, log the limitation before trying resolution
        if ('<' in className) {
            sink.log("vtable-templated-skip", "class '$className' has template args; _ZTV lookup unsupported in v1")
        }

        val addr = resolveVtableAddress(className, body, candidates) ?: return

        // 4. Apply data at the address.
        program.listing.clearCodeUnits(addr, addr.add(vtable.length.toLong() - 1), false)
        program.listing.createData(addr, vtable)
        sink.bookmark("vtable", addr, "applied $vtableName")
        ctx.diagnostics.recordVtable(className, "applied")

        // 5. Plate-comment each virtual method.
        var off = 0L
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
                    sink.log(
                        "vtable-virtual-unresolved",
                        "no Function at $mAddr for virtual method ${m.name} in $className",
                    )
                    ctx.diagnostics.recordVtable(className, "failed", reason = "virtual-method-unresolved")
                }
            } else {
                sink.log(
                    "vtable-virtual-unresolved",
                    "virtual method '${m.name}' in $className: no mangled symbol or unresolved address",
                )
                ctx.diagnostics.recordVtable(className, "failed", reason = "virtual-method-unresolved")
            }
            off += ptrSize
        }
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
            program.symbolTable.symbolIterator.firstOrNull {
                (it.name.startsWith("_ZTV") || it.name.startsWith("__ZTV")) &&
                    VtableSymbolCandidates.itaniumDecodesToClass(it.name, className)
            }?.let { return it.address }
        } catch (e: IllegalArgumentException) {
            sink.log("vtable-symbol-scan-error", "exception scanning symbol table for $className: ${e.message}")
        }

        // Step 3: Fallback to .rdata memory scan
        val rdataBlock = program.memory.getBlock(".rdata")
        if (rdataBlock != null) {
            try {
                program.symbolTable
                    .getSymbolIterator(rdataBlock.start, true)
                    .asIterable()
                    .asSequence()
                    .takeWhile { it.address < rdataBlock.end }
                    .firstOrNull {
                        (it.name.startsWith("_ZTV") || it.name.startsWith("__ZTV")) &&
                            VtableSymbolCandidates.itaniumDecodesToClass(it.name, className)
                    }?.let { return it.address }
            } catch (e: IllegalArgumentException) {
                sink.log("vtable-rdata-scan-error", "exception scanning .rdata for $className: ${e.message}")
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
        sink.log(
            "vtable-failed-$failureBucket",
            "class '$className': vtable not found (tried ${candidates.joinToString()})",
        )

        return null
    }

    /**
     * Resolve each base's class struct via TypeRegistry, then collect its
     * virtual methods (we look up the original AST via a `byName: Map<String, TypeDecl.Struct>`
     * registry passed into ClassBuilder). Returns inherited methods in declaration
     * order of `body.bases`.
     */
    private fun collectInheritedVirtuals(body: TypeDecl.Struct): List<MethodDecl> {
        val out = mutableListOf<MethodDecl>()
        for (base in body.bases) {
            val baseStruct = ClassBuilderHelpers.resolveBaseAstStatic(base.type, structAstsByName, typeAstsById)
                ?: continue
            out += baseStruct.methods.filter { it.virt == VirtKind.VIRTUAL }
        }
        return out.sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
    }

    /**
     * Match overrides by simple name (sufficient for non-overloaded virtual
     * methods, which is the Cygwin gcc 3.4.4 / xapasmcsr.exe corpus). For full
     * Itanium override matching we'd need parameter-type comparison after
     * type resolution — surfaced as v1.1 work.
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
    internal fun firstPolymorphicBase(body: TypeDecl.Struct): BaseDecl? =
        ClassBuilderHelpers.firstPolymorphicBase(body, structAstsByName, typeAstsById)

    internal fun hasPolymorphicBaseSubobject(body: TypeDecl.Struct): Boolean =
        ClassBuilderHelpers.hasPolymorphicBaseSubobject(body, structAstsByName, typeAstsById)
}

/**
 * Static helpers for polymorphic base detection (extracted for pure unit testing).
 */
internal object ClassBuilderHelpers {
    fun hasPolymorphicBaseSubobject(
        body: TypeDecl.Struct,
        structAstsByName: Map<String, TypeDecl.Struct>,
        typeAstsById: Map<TypeId, TypeAst>? = null,
    ): Boolean = firstPolymorphicBase(body, structAstsByName, typeAstsById) != null

    fun firstPolymorphicBase(
        body: TypeDecl.Struct,
        structAstsByName: Map<String, TypeDecl.Struct>,
        typeAstsById: Map<TypeId, TypeAst>? = null,
    ): BaseDecl? = body.bases
        .sortedBy { it.offsetBits }
        .firstOrNull { base ->
            val baseStruct =
                resolveBaseAstStatic(base.type, structAstsByName, typeAstsById) ?: return@firstOrNull false
            baseStruct.hasVTablePointerMarker ||
                baseStruct.methods.any { it.virt == VirtKind.VIRTUAL } ||
                firstPolymorphicBase(baseStruct, structAstsByName, typeAstsById) != null
        }

    fun resolveBaseAstStatic(
        typeDecl: TypeDecl,
        structAstsByName: Map<String, TypeDecl.Struct>,
        typeAstsById: Map<TypeId, TypeAst>? = null,
    ): TypeDecl.Struct? = when (typeDecl) {
        // Look up by TypeId using the byId map
        is TypeDecl.Ref -> typeAstsById?.get(typeDecl.id)?.body as? TypeDecl.Struct

        // Cross-reference by tagName: look in structAstsByName
        is TypeDecl.XRef -> structAstsByName[typeDecl.tagName]

        // Inline definition: extract the struct body directly
        is TypeDecl.InlineDef -> typeDecl.body as? TypeDecl.Struct

        else -> null
    }
}
