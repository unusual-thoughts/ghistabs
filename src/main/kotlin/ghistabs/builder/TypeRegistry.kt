package ghistabs.builder

import ghidra.program.model.data.*
import ghistabs.diag.DiagnosticSink
import ghistabs.diag.GapRecord
import ghistabs.diag.StabsDiagnostics
import ghistabs.parser.*

class TypeRegistry(
    private val dtm: DataTypeManager,
    private val sink: DiagnosticSink,
    private val diagnostics: StabsDiagnostics,
    private val harvest: Harvest,
) : DiagnosticSink by sink {
    private val byId = mutableMapOf<GlobalTypeId, DataType>()
    private val placeholders = mutableMapOf<GlobalTypeId, DataType>()
    private val byHash = mutableMapOf<Pair<String, Int>, DataType>()
    private val byPath = mutableMapOf<Pair<CategoryPath, String>, Int>()
    private val conflictCount = mutableMapOf<String, Int>()
//    private var unnamedCount = 0

//    fun newUnnamed(type: String) = "${type}_${unnamedCount++}"
//
//    fun tryGetExisting(id: LocalTypeId, cu: SourceFile.CUSource) = fileResolver.globalIdForCu(id, cu)?.let { gId ->
//        byId[gId] ?: placeholders[gId] ?: typeResolver.getTypeFor(id, cu)?.let { raw ->
//            makePlaceholder(raw.body, CategoryPath("/stabs"), raw.name)
//                .also { placeholders[gId] = it }
//        }
//    }

    fun tryGetExisting(gId: GlobalTypeId) = byId[gId] ?: placeholders[gId] ?: harvest.getType(gId)?.let { raw ->
        makePlaceholder(raw, CategoryPath("/stabs")).also { placeholders[gId] = it }
    }

    fun materialiseAll() {
        // gcc reuses local type IDs inside BINCL blocks per-CU: every CU's stab stream
        // emits its own private types inside e.g. `BINCL project_header.h` using local
        // file slots that all canonicalise to the same canonical CU. So multiple ASTs
        // legitimately share an `id` post-canonicalisation but describe DIFFERENT types.
        // Process every TypeAst; do NOT pre-dedupe by id. Ref resolution still uses
        // byId (last writer wins) — fine because refs are always emitted IN THE SAME CU
        // as the type they reference, so all CUs see consistent local→canonical lookups.
        //

        val tx = dtm.startTransaction("ghidra-stabs build types")
        try {
            // Pre-seed placeholders so forward refs within the batch resolve during body
            // materialisation. For Struct/Union bodies we ALSO addDataType the placeholder
            // up-front: addDataType returns the DTM-resolved instance and later mutations
            // on it land on the DTM-resident object. Without this, when two ASTs with the
            // same (name, category) but different bodies both materialise, the second one's
            // empty-vs-real conflict in registerWithConflict overwrites the first's
            // components.
            //
            // Non-aggregate placeholders (Enum etc.) are NOT pre-added — makePlaceholder
            // returns a Structure stub for them, and pre-adding it would later conflict
            // with the real EnumDataType during resolve() and cause it to be renamed to
            // `<name>_2`.
            for ((id, ast) in harvest.typeAsts) {
                val category = Attribution.categoryFor(ast.ghidraName, harvest.definingCUs(ast), diagnostics)
                val raw = makePlaceholder(ast, category)
                val placeholder = if (ast.body is TypeDecl.Struct) {
                    dtm.addDataType(raw, DataTypeConflictHandler.KEEP_HANDLER)
                } else {
                    raw
                }
                // First placeholder per id also goes in placeholders[id] so Ref(id) lookups
                // during materialisation get something. Later distinct-name ASTs at the
                // same id keep their own placeholderByIdName but DON'T overwrite the id-keyed
                // entry — refs by id should remain stable across the batch.
                placeholders.getOrPut(id) { placeholder }
            }
            for (ast in harvest.typeAsts.values) {
                resolve(ast)
            }
        } finally {
            dtm.endTransaction(tx, true)
        }
    }

    /**
     * Resolve a TypeDecl encountered inside another type's body (a field's type, a pointer's
     * pointee, a base class's type expression) to a Ghidra DataType.
     *
     * Per kind:
     * - **Ref / InlineDef**: look the TypeId up via byId → placeholders → harvest.
     *   Cycle-safe (placeholders break self-recursion).
     * - **Builtin / Range / Complex / WithSizeAttr**: delegated to [BuiltinTable].
     * - **Pointer / Reference / Const / Volatile / Array**: recurse on the inner type.
     * - **Struct / Enum / FunctionT / Method / XRef**: returns `null`. These aggregate bodies
     *   only have meaning when keyed by a [LocalTypeId]. The DataType for them is the one
     *   registered under that id during [materialiseAll]; passing the body itself loses
     *   that identity, so there is no defined lookup. Callers in possession of the parent
     *   [TypeAst.id] should use `byId[id]` (e.g. inside materialiseBody); callers outside
     *   the registry should look up the materialised type by category+name in the DTM
     *   (see ClassBuilder.build for the canonical pattern).
     */
    fun dataTypeFor(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        is TypeDecl.Ref -> tryGetExisting(decl.id)

        is TypeDecl.InlineDef -> {
            tryGetExisting(decl.id) ?: dataTypeFor(decl.body)?.apply {
                byId[decl.id] = this
            }
        }

        is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin -> {
            BuiltinTable.resolve(decl)
        }

        is TypeDecl.Pointer -> PointerDataType(dataTypeFor(decl.pointee) ?: Undefined4DataType.dataType, 4, dtm)

        is TypeDecl.Reference -> PointerDataType(dataTypeFor(decl.referent) ?: Undefined4DataType.dataType, 4, dtm)

        is TypeDecl.Const -> dataTypeFor(decl.inner)

        is TypeDecl.Volatile -> dataTypeFor(decl.inner)

        is TypeDecl.Array -> {
            // For arrays of unresolved element types (e.g. globals whose
            // element refers to a TypeId not in the registry), fall back to
            // ByteDataType, NOT `Undefined1`. The latter is type-equivalent
            // to Ghidra's auto-analysis-placed "this is undefined" bytes, so
            // a downstream data-reference analyzer that sees scalar refs to
            // our array happily re-coalesces it into the `undefined4` form
            // it would have built without us. `byte` is a concrete primitive
            // and survives the round-trip.
            val elem = dataTypeFor(decl.element) ?: ByteDataType.dataType
            // Length resolution priority:
            //   1. `decl.length` (explicit element count from the stab)
            //   2. derive from `indexType` Range as `max - min + 1`
            //      (gcc stabs frequently omit `length` and only encode the
            //      array bound via the index Range — e.g. `BranchInstructions`
            //      = array of EnumInstToken indexed 0..15 → 16 elements)
            //   3. fall back to 1 so ArrayDataType doesn't throw
            val rangeLen = (decl.indexType as? TypeDecl.Range)
                ?.let { it.max - it.min + 1 }
                ?.takeIf { it > 0 }
            val numElements = (decl.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
            ArrayDataType(elem, numElements, elem.length)
        }

        is TypeDecl.FunctionT -> {
            val fd = FunctionDefinitionDataType(CategoryPath("/stabs/unnamed"), "FUNCTION_${decl.hashCode()}", dtm)
            fd.returnType = dataTypeFor(decl.ret) ?: VoidDataType()
            val params = decl.params.mapIndexed { i, p ->
                ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: Undefined4DataType.dataType, null)
            }.toTypedArray()
            fd.setArguments(*params)
            fd
        }

        // FIXME: why the two cases ???
        is TypeDecl.XRef if decl.kind == AggrKind.STRUCT -> harvest.getByXRef(decl)?.let { tryGetExisting(it.id) }

        is TypeDecl.XRef -> harvest.getByXRef(decl)?.let { dataTypeFor(it.body) }

        // Aggregate bodies — never referenced directly; only meaningful via TypeId.
        // See kdoc above.
        is TypeDecl.Struct, is TypeDecl.Enum, is TypeDecl.Method -> {
            log("referenced-aggregate", "asked for ref to $decl")
            null
        }
    }

    private fun makePlaceholder(ast: TypeAst, category: CategoryPath, reason: String = "fwd-decl"): DataType {
        val dt = when (ast.body) {
            is TypeDecl.Struct if (ast.body.kind == AggrKind.UNION) -> UnionDataType(category, ast.ghidraName, dtm)
            is TypeDecl.Struct -> StructureDataType(category, ast.ghidraName, ast.body.sizeBytes.toInt(), dtm)
            else -> StructureDataType(category, ast.ghidraName, 0, dtm)
        }
        diagnostics.recordPlaceholder(ast.name, category.toString(), reason)
        return dt
    }

    private fun resolve(ast: TypeAst): DataType {
        // 2. Compute content hash for cross-CU dedup. Uses Harvest.contentHash,
        // which treats Refs as content-equivalent when they point at types
        // with the same (name, body-kind) — so per-CU template-instantiation
        // clones collapse onto a single canonical DataType.
        val hash = harvest.contentHash(ast.body)

        // 3. Cross-CU dedup: same name + same body seen before? Reuse the canonical
        //    DataType and STOP — re-materialising the body onto a different placeholder
        //    would let the resulting empty-vs-real conflict in registerWithConflict
        //    overwrite the canonical (gap census on the duplicate is best-effort).
        byHash[ast.ghidraName to hash]?.let {
            byId.putIfAbsent(ast.id, it)
            return it
        }

        // 4. Compute category
        val category = Attribution.categoryFor(ast.ghidraName, harvest.definingCUs(ast), diagnostics)

        // 5. Reuse pre-seeded placeholder (or create one if resolve() is called directly)
        val placeholder = placeholders.getOrPut(ast.id) {
            makePlaceholder(ast, category, "ref-stub")
        }

        // 6. Materialise body — references back to ast.id will resolve via placeholders[ast.id]
        val materialised = materialiseBody(ast, category, placeholder)

        // 7. Register with conflict handling and record as fully resolved
        val canonical = registerWithConflict(materialised, ast.ghidraName, hash, category)
        // Keep byId stable for Ref lookups: first writer wins. (Later same-id ASTs
        // with different names still materialise into the DTM via byIdName but don't
        // hijack Ref(id) resolution.)
        byId.putIfAbsent(ast.id, canonical)
        byHash[ast.ghidraName to hash] = canonical

        return canonical
    }

    private fun materialiseBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType =
        when (val body = ast.body) {
            is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin ->
                BuiltinTable.resolve(body) ?: placeholder

            is TypeDecl.Pointer -> PointerDataType(
                dataTypeFor(body.pointee) ?: Undefined4DataType.dataType,
                4,
                dtm,
            )

            is TypeDecl.Reference -> PointerDataType(
                dataTypeFor(body.referent) ?: Undefined4DataType.dataType,
                4,
                dtm,
            )

            is TypeDecl.Const -> dataTypeFor(body.inner) ?: placeholder

            is TypeDecl.Volatile -> dataTypeFor(body.inner) ?: placeholder

            is TypeDecl.InlineDef -> dataTypeFor(body.body)?.apply {
                byId[body.id] = this
            } ?: placeholder

            is TypeDecl.Array -> {
                val elem = dataTypeFor(body.element) ?: ByteDataType.dataType
                val rangeLen = (body.indexType as? TypeDecl.Range)
                    ?.let { it.max - it.min + 1 }
                    ?.takeIf { it > 0 }
                val numElements = (body.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
                ArrayDataType(elem, numElements, elem.length)
            }

            is TypeDecl.Enum -> {
                val sizeBytes = 4 // GCC default
                val e = EnumDataType(category, ast.ghidraName, sizeBytes, dtm)
                for ((mname, mval) in body.members) {
                    e.add(mname, mval)
                }
                e
            }

            is TypeDecl.Struct -> {
                // Reuse the placeholder cast to the right type
                val struct: Composite = if (body.kind == AggrKind.UNION) {
                    placeholder as Union
                } else {
                    placeholder as Structure
                }

                // Phase 5: insert base classes as inlined components.
                if (struct is Structure) {
                    // Compute layout boundary to infer size of unresolved bases (offset of next base
                    // or first non-static field — that's where this base subobject must end).
                    val sortedBaseOffsetsBytes = body.bases.map { (it.offsetBits / 8).toInt() }.toSortedSet()
                    val firstFieldOffsetBytes = body.fields
                        .filter { !it.isStatic }
                        .minOfOrNull { (it.offsetBits / 8).toInt() }
                        ?: body.sizeBytes.toInt()

                    val dataTypeByOffset = mutableMapOf<Int, DataType>()
                    val resolvedBaseInfo = mutableMapOf<Int, ResolvedBase>()
                    for (base in body.bases) {
                        val offsetBytes = (base.offsetBits / 8).toInt()
                        val dt = dataTypeFor(base.type)
                        if (dt != null && dt.length > 0) {
                            dataTypeByOffset[offsetBytes] = dt
                            resolvedBaseInfo[offsetBytes] = ResolvedBase(dt.name, dt.length)
                            continue
                        }
                        // Synthesise a placeholder of the size implied by layout.
                        val nextOffset =
                            sortedBaseOffsetsBytes.firstOrNull { it > offsetBytes } ?: firstFieldOffsetBytes
                        val inferredSize = nextOffset - offsetBytes
                        if (inferredSize <= 0) {
                            log(
                                "base-skipped-zero-size",
                                "Base of '${ast.name}' at offset $offsetBytes: cannot infer size",
                            )
                            diagnostics.inc("base-skipped-zero-size")
                            continue
                        }
                        val synthName = "unknown_$offsetBytes"
                        val synthDt = ArrayDataType(Undefined1DataType.dataType, inferredSize, 1)
                        dataTypeByOffset[offsetBytes] = synthDt
                        resolvedBaseInfo[offsetBytes] = ResolvedBase(synthName, inferredSize)
                        log(
                            "base-synthesized",
                            "Base of '${ast.name}' at offset $offsetBytes: " +
                                "Ref unresolved, synthesised $inferredSize-byte placeholder",
                        )
                        diagnostics.inc("base-synthesized")
                    }

                    // Plan ops from resolved bases; supplement with synthesised ones.
                    val resolvedOps = BaseInsertionPlanner.planBaseInsertions(body.bases) {
                        val dt = dataTypeFor(it)
                        if (dt != null && dt.length > 0) {
                            ResolvedBase(dt.name, dt.length)
                        } else {
                            null
                        }
                    }
                    val resolvedOffsets = resolvedOps.map { it.offsetBytes }.toSet()
                    val synthOps = body.bases.mapNotNull { base ->
                        val off = (base.offsetBits / 8).toInt()
                        if (off in resolvedOffsets) return@mapNotNull null
                        val info = resolvedBaseInfo[off] ?: return@mapNotNull null
                        val fieldName =
                            if (base.isVirtual) "_vbase_${info.simpleName}" else "_base_${info.simpleName}"
                        val comment = buildString {
                            append(base.access.name.lowercase())
                            if (base.isVirtual) append(" virtual")
                            append(" base (unresolved type)")
                        }
                        InsertOp(off, fieldName, comment, info.simpleName)
                    }
                    val ops = (resolvedOps + synthOps).sortedBy { it.offsetBytes }
                    for (op in ops) {
                        val baseDt = dataTypeByOffset[op.offsetBytes] ?: continue
                        try {
                            struct.replaceAtOffset(
                                op.offsetBytes,
                                baseDt,
                                baseDt.length,
                                op.fieldName,
                                op.comment,
                            )
                            diagnostics.inc("inheritance-applied")
                        } catch (e: java.lang.IllegalArgumentException) {
                            log(
                                "base-layout",
                                "Failed to insert base '${op.baseSimpleName}' in '${ast.name}': ${e.message}",
                            )
                            diagnostics.inc("inheritance-failed")
                        }
                    }
                }

                // Compute polymorphic base for inherited vfptr gating
                val polyBase = ClassBuilderHelpers(harvest).firstPolymorphicBase(body)

                // Existing field loop (unchanged).
                for (field in body.fields) {
                    if (field.isStatic) continue // Skip static fields

                    // Skip parser-emitted _vptr$<class> field if inherited from polymorphic base
                    val isParserEmittedVptr =
                        field.name.startsWith("_vptr$") || field.name.startsWith("_vptr.") || field.name == "_vptr"
                    if (
                        isParserEmittedVptr &&
                        polyBase != null &&
                        field.offsetBits == polyBase.offsetBits
                    ) {
                        // Inherited vfptr — the _base_<Base> component already carries it. Skip.
                        diagnostics.inc("vptr-skipped-inherited")
                        continue
                    }

                    val ft = dataTypeFor(field.type) ?: Undefined4DataType.dataType
                    val len = if (ft.length <= 0) 4 else ft.length
                    try {
                        when (struct) {
                            is Structure -> struct.replaceAtOffset(
                                (field.offsetBits / 8).toInt(),
                                ft,
                                len,
                                field.name,
                                null,
                            )

                            is Union -> struct.add(ft, field.name, null)

                            else -> {}
                        }
                    } catch (e: Exception) {
                        log("field-layout", "Failed to add '${field.name}' to '${ast.name}': ${e.message}")
                    }
                }

                // Record gaps for this struct
                if (struct is Structure) {
                    val componentRecords: MutableList<Pair<String, Pair<Int, Int>>> = mutableListOf()
                    for (component in struct.components) {
                        componentRecords.add(Pair(component.fieldName, Pair(component.offset, component.length)))
                    }
                    val gaps = computeGaps(componentRecords, body.sizeBytes.toInt())
                    val qualifiedName = "$category/${ast.ghidraName}"
                    diagnostics.recordStructGaps(qualifiedName, gaps)
                }

                // Task 2: Plate-comment summary on the derived struct (base class metadata).
                if (body.bases.isNotEmpty() && struct is Structure) {
                    val lines = body.bases.sortedBy { it.offsetBits }.joinToString("\n") { base ->
                        val baseName = (dataTypeFor(base.type)?.name) ?: "<unresolved>"
                        val virt = if (base.isVirtual) " virtual" else ""
                        "inherits ${base.access.name.lowercase()}$virt $baseName @ +${base.offsetBits / 8}"
                    }
                    val existing = struct.description ?: ""
                    struct.description =
                        if (existing.isEmpty()) lines else "$existing\n$lines"
                }

                struct
            }

            is TypeDecl.FunctionT -> {
                val fd = FunctionDefinitionDataType(category, ast.ghidraName, dtm)
                fd.returnType = dataTypeFor(body.ret) ?: VoidDataType()
                val params = body.params.mapIndexed { i, p ->
                    ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: Undefined4DataType.dataType, null)
                }.toTypedArray()
                fd.setArguments(*params)
                fd
            }

            is TypeDecl.Method -> {
                val fd = FunctionDefinitionDataType(category, ast.ghidraName, dtm)
                fd.returnType = dataTypeFor(body.ret) ?: VoidDataType()
                val thisParam = ParameterDefinitionImpl(
                    "this",
                    dataTypeFor(body.cls) ?: Undefined4DataType.dataType,
                    null,
                )
                val otherParams =
                    body.params.mapIndexed { i, p ->
                        ParameterDefinitionImpl(
                            "arg$i",
                            dataTypeFor(p) ?: Undefined4DataType.dataType,
                            null,
                        )
                    }
                fd.setArguments(*(listOf(thisParam) + otherParams).toTypedArray())
                fd
            }

            is TypeDecl.XRef -> {
                // Resolve `XRef(kind, tagName)` to the canonical struct of
                // that name + kind so an `InlineDef(id, XRef(STRUCT, "Foo"))`
                // typeAst (often emitted by gcc for ABI-internal typeinfo
                // helpers like `__si_class_type_info_pseudo`) doesn't get
                // materialised as a separate empty `XRef_[...]` Structure
                // applied at typeinfo locations. Aliases this id to the
                // canonical DataType for `Foo` via byId.
                harvest.getByXRef(body)?.let { canonical ->
                    tryGetExisting(canonical.id)?.also { byId[ast.id] = it }
                } ?: run {
                    log("xref-stub", "Forward ref to '${body.tagName}'; materialising stub")
                    placeholder
                }
            }

            // Truly-missing classifier: harvest already exhausted above.
//                val knownTypeIds = emptySet<LocalTypeId>()

//                val classification = ResolverDecision.classifyRef(
//                    body.id,
//                    ast.id.source.cu,
//                    knownTypeIds,
//                    knownFileNums,
//                )
//                val gId = fileResolver.globalIdForCu(body.id)
//                val gId = body.id
            is TypeDecl.Ref -> tryGetExisting(body.id) ?: run {
                log("dangling-ref", "Dangling ref to ${body.id} in '${ast.name}' from ${ast.source} CU ${ast.cu} ")
                diagnostics.recordUnresolvedRef(body.id, ast.name)
                diagnostics.inc("dangling-ref")
                Undefined4DataType.dataType
            }
        }

    private fun registerWithConflict(dt: DataType, name: String, hash: Int, category: CategoryPath): DataType {
        val existing = dtm.getDataType(category, name)
        if (existing == null) {
            byPath[category to name] = hash
            return dtm.addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)
        }
        // Same hash → idempotent
        val existingHash = byPath[category to name]
        if (existingHash == hash) {
            return existing
        }
        // Different body → try merge if both are Structures
        if (dt is Structure && existing is Structure) {
            val mergeResult = tryExecuteMerge(existing, dt, name, category, hash)
            if (mergeResult != null) {
                return mergeResult
            }
        }

        // Drop the duplicate. The `_N`-rename path used to allocate a fresh
        // DataType slot but no consumer ever references the rename — Refs
        // resolve through `byId` to the canonical entry, and `byHash`
        // dedups same-content by name. The rename was particularly costly
        // on C++ template-internal typedefs (`_ValueType`, `_Is_POD`, etc.)
        // where every CU's instantiation has its own per-CU body and the
        // count exploded into the thousands; each rename did a DataType
        // clone + DTM addType + log line. First-writer-wins via the
        // existing canonical entry is correct and ~100x faster on
        // template-heavy binaries.
        diagnostics.recordDedup(kind = "drop", name = name, detail = "first-writer-wins")
        return existing
//        // Fall back to renaming: find a free _N slot
//        // EXCEPT for Structures in conflict: drop them entirely (no _N renaming)
//        if (dt is Structure && existing is Structure) {
//            // Already tried merge and it failed; was logged via recordDedup in tryExecuteMerge
//            return existing
//        }
//        var n = (conflictCount[name] ?: 1) + 1
//        while (true) {
//            val candidate = "${name}_$n"
//            if (dtm.getDataType(category, candidate) == null) break
//            n++
//            if (n > 1000) error("cannot allocate conflict suffix for '$name'")
//        }
//        conflictCount[name] = n
//        // Clone and rename
//        val copy = dt.copy(dtm)
//        copy.name = "${name}_$n"
//        log("type-conflict", "Two definitions of '$name' with different bodies; second renamed to '${name}_$n'")
//        diagnostics.recordDedup(kind = "rename", name = name, detail = "renamed-to-${name}_$n")
//        byPath[category to "${name}_$n"] = hash
//        return dtm.addDataType(copy, DataTypeConflictHandler.KEEP_HANDLER)
    }

    /**
     * Try to merge two structures via byte-coverage algorithm.
     * Returns the merged structure if successful, null if conflict or identical.
     */
    private fun tryExecuteMerge(
        existing: Structure,
        incoming: Structure,
        name: String,
        category: CategoryPath,
        incomingHash: Int,
    ): DataType? {
        val existingComp = existing.toComponentRecords()
        val incomingComp = incoming.toComponentRecords()
        return when (val result = StructuralDiff.diff(existingComp, existing.length, incomingComp, incoming.length)) {
            // Same structure layout, already idempotent
            StructDiffResult.Identical -> existing

            // Execute the merge plan
            is StructDiffResult.GapMergeable -> {
                val incomingByOffset = incomingComp.associateBy { it.offsetBytes }
                val existingByOffset = existingComp.associateBy { it.offsetBytes }

                for (op in result.mergePlan) {
                    val sourceComponent = op.sourceComponent

                    // Fetch the actual DataTypeComponent from the source side
                    val sourceDataTypeComponent =
                        if (op.sourceFromLeft) {
                            // Source is from existing
                            existing.components.find { it.offset == sourceComponent.offsetBytes }
                        } else {
                            // Source is from incoming
                            incoming.components.find { it.offset == sourceComponent.offsetBytes }
                        }

                    if (sourceDataTypeComponent != null) {
                        try {
                            existing.replaceAtOffset(
                                sourceComponent.offsetBytes,
                                sourceDataTypeComponent.dataType,
                                sourceDataTypeComponent.length,
                                sourceDataTypeComponent.fieldName,
                                sourceDataTypeComponent.comment,
                            )
                        } catch (e: IllegalArgumentException) {
                            log(
                                "merge-failed",
                                "Could not apply merge to '$name' at offset ${sourceComponent.offsetBytes}: ${e.message}",
                            )
                            return null
                        }
                    }
                }

                // Update hash to reflect the new merged content
                byPath[category to name] = incomingHash
                diagnostics.recordDedup(kind = "merge", name = name, detail = "merged ${result.mergePlan.size} fields")
                log("dedup-merged", "$name: ${result.mergePlan.size} fields merged")
                existing
            }

            is StructDiffResult.Conflicting -> {
                // Structural conflict: drop the new one (don't merge)
                diagnostics.recordDedup(kind = "drop", name = name, result.reason)
                null
            }
        }
    }

    /**
     * Find a DataType by simple name (not full path).
     * Conservative: returns null if not found OR if ambiguous (multiple matches).
     * Logs ambiguity with a numeric counter for surfacing unresolved ambiguities.
     *
     * This is used by DemanglerReplacer to locate replacement types for demangler stubs.
     * Ambiguity is logged and counted but NOT resolved heuristically (too risky for type safety).
     *
     * @param simpleName the unqualified type name to search for
     * @return the unique DataType if exactly one match, null if not found or ambiguous
     */
    fun findByName(simpleName: String): DataType? {
        val candidates = mutableListOf<Pair<CategoryPath, String>>()
        for ((key, _) in byPath) {
            if (key.second == simpleName) {
                candidates.add(key)
            }
        }
        return when {
            candidates.isEmpty() -> null

            candidates.size == 1 -> dtm.getDataType(candidates[0].first, candidates[0].second)

            else -> {
                // Multiple matches: ambiguous. Log and count.
                log("demangler-ambiguous", "Multiple matches for '$simpleName': $candidates")
                diagnostics.inc("demangler-ambiguous")
                null
            }
        }
    }
}

/**
 * Pure function to compute gaps in a struct's field layout.
 * Takes component records and total struct size, returns list of gaps.
 *
 * @param componentRecords List of fields with offset and length in bytes
 * @param totalLengthBytes Total size of struct in bytes
 * @return List of gaps; empty if fully packed or no components
 */
fun computeGaps(componentRecords: List<Pair<String, Pair<Int, Int>>>, totalLengthBytes: Int): List<GapRecord> {
    if (componentRecords.isEmpty()) return emptyList()

    val gaps = mutableListOf<GapRecord>()
    // Sort by offset
    val sorted = componentRecords.sortedBy { it.second.first }

    // Check for gaps between consecutive fields
    for (i in 0 until sorted.size - 1) {
        val (currName, currMetrics) = sorted[i]
        val (nextName, nextMetrics) = sorted[i + 1]
        val currOffset = currMetrics.first
        val currLength = currMetrics.second
        val nextOffset = nextMetrics.first
        val currEnd = currOffset + currLength

        if (currEnd < nextOffset) {
            val gapLength = nextOffset - currEnd
            gaps.add(
                GapRecord(
                    offsetBits = (currEnd * 8).toLong(),
                    lengthBits = (gapLength * 8).toLong(),
                    prevField = currName,
                    nextField = nextName,
                ),
            )
        }
    }

    // Check for trailing gap
    val lastRecord = sorted.last()
    val lastOffset = lastRecord.second.first
    val lastLength = lastRecord.second.second
    val lastEnd = lastOffset + lastLength
    if (lastEnd < totalLengthBytes) {
        val trailingGapLength = totalLengthBytes - lastEnd
        gaps.add(
            GapRecord(
                offsetBits = (lastEnd * 8).toLong(),
                lengthBits = (trailingGapLength * 8).toLong(),
                prevField = lastRecord.first,
                nextField = null,
            ),
        )
    }

    return gaps
}
