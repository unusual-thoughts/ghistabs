package ghistabs.builder

import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.EnumDataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinitionImpl
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.data.Union
import ghidra.program.model.data.UnionDataType
import ghidra.program.model.data.VoidDataType
import ghistabs.diag.GapRecord
import ghistabs.diag.StabsDiagnostics
import ghistabs.importer.BookmarkSink
import ghistabs.parser.AggrKind
import ghistabs.parser.IncludeContext
import ghistabs.parser.TypeDecl
import ghistabs.parser.TypeId

@JvmInline
value class ContentHash(
    val v: Long,
) {
    companion object {
        fun of(decl: TypeDecl): ContentHash = ContentHash(hashDecl(decl))

        private fun hashDecl(decl: TypeDecl): Long {
            var h = 0L
            h = h * 31 +
                when (decl) {
                    is TypeDecl.Ref -> 1L
                    is TypeDecl.Range -> 2L
                    is TypeDecl.Pointer -> 3L
                    is TypeDecl.Reference -> 4L
                    is TypeDecl.Const -> 5L
                    is TypeDecl.Volatile -> 6L
                    is TypeDecl.Array -> 7L
                    is TypeDecl.Enum -> 8L
                    is TypeDecl.Struct -> 9L
                    is TypeDecl.FunctionT -> 10L
                    is TypeDecl.Method -> 11L
                    is TypeDecl.Complex -> 12L
                    is TypeDecl.XRef -> 13L
                    is TypeDecl.WithSizeAttr -> 14L
                    is TypeDecl.InlineDef -> 15L
                    TypeDecl.Builtin -> 16L
                }

            h =
                when (decl) {
                    is TypeDecl.Ref -> {
                        h * 31 + decl.id.cu.toLong() * 31 + decl.id.n.toLong()
                    }

                    is TypeDecl.Range -> {
                        h * 31 + decl.of.cu.toLong() * 31 + decl.of.n.toLong() + decl.min.hashCode().toLong() * 31 +
                            decl.max.hashCode().toLong()
                    }

                    is TypeDecl.Pointer -> {
                        h * 31 + hashDecl(decl.pointee)
                    }

                    is TypeDecl.Reference -> {
                        h * 31 + hashDecl(decl.referent)
                    }

                    is TypeDecl.Const -> {
                        h * 31 + hashDecl(decl.inner)
                    }

                    is TypeDecl.Volatile -> {
                        h * 31 + hashDecl(decl.inner)
                    }

                    is TypeDecl.Array -> {
                        h * 31 + hashDecl(decl.element) + (decl.length?.hashCode()?.toLong() ?: 0L) +
                            (decl.indexType?.let { hashDecl(it) } ?: 0L)
                    }

                    is TypeDecl.Enum -> {
                        decl.members.fold(h * 31) { acc, p -> acc * 31 + p.first.hashCode().toLong() * 31 + p.second }
                    }

                    is TypeDecl.Struct -> {
                        var sh = h * 31 + decl.kind.hashCode().toLong()
                        sh = sh * 31 + decl.sizeBytes
                        sh =
                            decl.fields.fold(sh) { acc, f ->
                                acc * 31 + f.name.hashCode().toLong() * 31 + hashDecl(f.type)
                            }
                        sh = decl.methods.fold(sh) { acc, m -> acc * 31 + m.name.hashCode().toLong() }
                        sh
                    }

                    is TypeDecl.FunctionT -> {
                        h * 31 + hashDecl(decl.ret) + decl.params.fold(0L) { acc, p -> acc * 31 + hashDecl(p) }
                    }

                    is TypeDecl.Method -> {
                        h * 31 + hashDecl(decl.cls) + hashDecl(decl.ret) +
                            decl.params.fold(0L) { acc, p -> acc * 31 + hashDecl(p) }
                    }

                    is TypeDecl.Complex -> {
                        h * 31 + decl.rCode.toLong() + decl.sizeBytes.toLong()
                    }

                    is TypeDecl.XRef -> {
                        h * 31 + decl.kind.hashCode().toLong() + decl.tagName.hashCode().toLong()
                    }

                    is TypeDecl.WithSizeAttr -> {
                        h * 31 + decl.sizeBits.toLong() + hashDecl(decl.inner)
                    }

                    is TypeDecl.InlineDef -> {
                        h * 31 + decl.id.cu.toLong() * 31 + decl.id.n.toLong() + hashDecl(decl.body)
                    }

                    TypeDecl.Builtin -> {
                        h
                    }
                }
            return h
        }
    }
}

data class TypeAst(
    val id: TypeId,
    val name: String,
    val body: TypeDecl,
    val cuFile: String,
)

class TypeRegistry(
    private val dtm: DataTypeManager,
    private val sink: BookmarkSink,
    private val diagnostics: StabsDiagnostics,
) {
    private val byId: MutableMap<TypeId, DataType> = mutableMapOf()
    private val placeholders: MutableMap<TypeId, DataType> = mutableMapOf()
    private val byHash: MutableMap<Pair<String, ContentHash>, DataType> = mutableMapOf()
    private val byPath: MutableMap<Pair<CategoryPath, String>, ContentHash> = mutableMapOf()
    private val conflictCount: MutableMap<String, Int> = mutableMapOf()
    private var rawByIdSnapshot: Map<TypeId, TypeAst> = emptyMap()
    private var includeContextsByFile: Map<String, IncludeContext> = emptyMap()
    private var structAstsByName: Map<String, TypeDecl.Struct> = emptyMap()

    fun setIncludeContexts(contexts: Map<String, IncludeContext>) {
        includeContextsByFile = contexts
    }

    fun materialiseAll(
        rawTypesById: Map<TypeId, TypeAst>,
        attribution: (String, Set<String>) -> CategoryPath,
    ) {
        // Snapshot for cross-batch fallback in dataTypeFor
        rawByIdSnapshot = rawTypesById
        val asts = rawTypesById.values.toList()
        val byName = asts.groupBy { it.name }

        // Build struct AST map for polymorphic base detection in materialiseBody
        structAstsByName =
            asts
                .mapNotNull { ast ->
                    val body = ast.body as? TypeDecl.Struct ?: return@mapNotNull null
                    ast.name to body
                }.toMap()

        val tx = dtm.startTransaction("ghidra-stabs build types")
        try {
            // Pre-seed placeholders in a SEPARATE map so forward refs within the batch
            // resolve to the placeholder during body materialization. byId is reserved
            // for fully-resolved types so that resolve() doesn't short-circuit.
            for (ast in asts) {
                if (placeholders.containsKey(ast.id) || byId.containsKey(ast.id)) continue
                val defCUs = byName[ast.name]?.map { it.cuFile }?.toSet() ?: setOf(ast.cuFile)
                val category = attribution(ast.name, defCUs)
                placeholders[ast.id] = makePlaceholder(ast.body, category, ast.name)
            }
            for (ast in asts) {
                resolve(ast, byName, attribution)
            }
        } finally {
            dtm.endTransaction(tx, true)
        }
    }

    fun dataTypeFor(decl: TypeDecl): DataType? =
        when (decl) {
            // Check byId first (fully resolved), then placeholders (cycle-breaking),
            // then rawByIdSnapshot (fallback for forward refs to not-yet-resolved types)
            is TypeDecl.Ref -> {
                byId[decl.id]
                    ?: placeholders[decl.id]
                    ?: rawByIdSnapshot[decl.id]?.let { ast ->
                        makePlaceholder(ast.body, CategoryPath("/stabs"), ast.name)
                            .also { placeholders[decl.id] = it }
                    }
            }

            is TypeDecl.InlineDef -> {
                byId[decl.id]
                    ?: placeholders[decl.id]
                    ?: rawByIdSnapshot[decl.id]?.let { ast ->
                        makePlaceholder(ast.body, CategoryPath("/stabs"), ast.name)
                            .also { placeholders[decl.id] = it }
                    } ?: dataTypeFor(decl.body)
            }

            is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.WithSizeAttr -> {
                BuiltinTable.resolve(decl, dtm)
            }

            is TypeDecl.Pointer -> {
                val inner = dataTypeFor(decl.pointee)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Reference -> {
                val inner = dataTypeFor(decl.referent)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Const -> {
                dataTypeFor(decl.inner)
            }

            is TypeDecl.Volatile -> {
                dataTypeFor(decl.inner)
            }

            is TypeDecl.Array -> {
                val elem = dataTypeFor(decl.element) ?: return null
                ArrayDataType(elem, (decl.length ?: 0L).toInt().coerceAtLeast(0), elem.length)
            }

            else -> {
                null
            } // Struct, Enum, FunctionT, Method, XRef must have been registered via materialiseAll
        }

    private fun makePlaceholder(
        body: TypeDecl,
        category: CategoryPath,
        name: String,
        reason: String = "fwd-decl",
    ): DataType {
        val dt =
            when (body) {
                is TypeDecl.Struct -> {
                    if (body.kind == AggrKind.UNION) {
                        UnionDataType(category, name, dtm)
                    } else {
                        StructureDataType(category, name, body.sizeBytes.toInt(), dtm)
                    }
                }

                else -> {
                    StructureDataType(category, name, 0, dtm)
                }
            }
        diagnostics.recordPlaceholder(name, category.toString(), reason)
        return dt
    }

    private fun resolve(
        ast: TypeAst,
        byName: Map<String, List<TypeAst>>,
        attribution: (String, Set<String>) -> CategoryPath,
    ): DataType {
        // 1. Already fully resolved?
        byId[ast.id]?.let { return it }

        // 2. Compute content hash for cross-CU dedup
        val hash = ContentHash.of(ast.body)

        // 3. Cross-CU dedup: same name + same body seen before?
        // NOTE: Gap census is best-effort per first-materialization.
        // Duplicate structs (found here) skip gap computation and reuse the canonical type.
        // This is acceptable since truly identical structures have identical gaps anyway.
        byHash[ast.name to hash]?.let { existing ->
            byId[ast.id] = existing
            return existing
        }

        // 4. Compute category
        val definingCUs = byName[ast.name]?.map { it.cuFile }?.toSet() ?: setOf(ast.cuFile)
        val category = attribution(ast.name, definingCUs)

        // 5. Reuse pre-seeded placeholder (or create one if resolve() is called directly)
        val placeholder = placeholders.getOrPut(ast.id) { makePlaceholder(ast.body, category, ast.name, "ref-stub") }

        // 6. Materialise body — references back to ast.id will resolve via placeholders[ast.id]
        val materialised = materialiseBody(ast, category, placeholder)

        // 7. Register with conflict handling and record as fully resolved
        val canonical = registerWithConflict(materialised, ast.name, hash, category)
        byId[ast.id] = canonical
        byHash[ast.name to hash] = canonical

        return canonical
    }

    private fun materialiseBody(
        ast: TypeAst,
        category: CategoryPath,
        placeholder: DataType,
    ): DataType =
        when (val body = ast.body) {
            is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.WithSizeAttr -> {
                BuiltinTable.resolve(body, dtm) ?: placeholder
            }

            is TypeDecl.Pointer -> {
                val inner = dataTypeFor(body.pointee)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Reference -> {
                val inner = dataTypeFor(body.referent)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Const -> {
                dataTypeFor(body.inner) ?: placeholder
            }

            is TypeDecl.Volatile -> {
                dataTypeFor(body.inner) ?: placeholder
            }

            is TypeDecl.InlineDef -> {
                dataTypeFor(body.body) ?: placeholder
            }

            is TypeDecl.Array -> {
                val elem = dataTypeFor(body.element) ?: Undefined4DataType.dataType
                ArrayDataType(elem, (body.length ?: 0L).toInt().coerceAtLeast(0), elem.length)
            }

            is TypeDecl.Enum -> {
                val sizeBytes = 4 // GCC default
                val e = EnumDataType(category, ast.name, sizeBytes, dtm)
                for ((mname, mval) in body.members) {
                    e.add(mname, mval)
                }
                e
            }

            is TypeDecl.Struct -> {
                // Reuse the placeholder cast to the right type
                val struct: Composite =
                    if (body.kind == AggrKind.UNION) {
                        placeholder as Union
                    } else {
                        placeholder as Structure
                    }

                // Phase 5: insert base classes as inlined components.
                if (struct is Structure) {
                    val resolveBase: (TypeDecl) -> ResolvedBase? = { typeDecl ->
                        val dt = dataTypeFor(typeDecl)
                        if (dt == null) {
                            null
                        } else {
                            ResolvedBase(simpleName = dt.name, lengthBytes = dt.length)
                        }
                    }
                    val dataTypeByOffset = mutableMapOf<Int, DataType>()
                    for (base in body.bases) {
                        val dt = dataTypeFor(base.type)
                        if (dt != null) {
                            dataTypeByOffset[(base.offsetBits / 8).toInt()] = dt
                        }
                    }

                    val ops = BaseInsertionPlanner.planBaseInsertions(body.bases, resolveBase)
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
                            sink.log(
                                "base-layout",
                                "Failed to insert base '${op.baseSimpleName}' in '${ast.name}': ${e.message}",
                            )
                            diagnostics.inc("inheritance-failed")
                        }
                    }
                }

                // Compute polymorphic base for inherited vfptr gating
                val polyBase = ClassBuilderHelpers.firstPolymorphicBase(body, structAstsByName)

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
                            is Structure -> {
                                struct.replaceAtOffset((field.offsetBits / 8).toInt(), ft, len, field.name, null)
                            }

                            is Union -> {
                                struct.add(ft, field.name, null)
                            }

                            else -> {}
                        }
                    } catch (e: Exception) {
                        sink.log("field-layout", "Failed to add '${field.name}' to '${ast.name}': ${e.message}")
                    }
                }

                // Record gaps for this struct
                if (struct is Structure) {
                    val componentRecords: MutableList<Pair<String, Pair<Int, Int>>> = mutableListOf()
                    for (component in struct.components) {
                        componentRecords.add(Pair(component.fieldName, Pair(component.offset, component.length)))
                    }
                    val gaps = computeGaps(componentRecords, body.sizeBytes.toInt())
                    val qualifiedName = "$category/${ast.name}"
                    diagnostics.recordStructGaps(qualifiedName, gaps)
                }

                // Task 2: Plate-comment summary on the derived struct (base class metadata).
                if (body.bases.isNotEmpty() && struct is Structure) {
                    val lines =
                        body.bases.sortedBy { it.offsetBits }.joinToString("\n") { base ->
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
                val fd = FunctionDefinitionDataType(category, ast.name, dtm)
                fd.returnType = dataTypeFor(body.ret) ?: VoidDataType()
                val params =
                    body.params
                        .mapIndexed { i, p ->
                            ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: Undefined4DataType.dataType, null)
                        }.toTypedArray()
                fd.setArguments(*params)
                fd
            }

            is TypeDecl.Method -> {
                val fd = FunctionDefinitionDataType(category, ast.name, dtm)
                fd.returnType = dataTypeFor(body.ret) ?: VoidDataType()
                val thisParam =
                    ParameterDefinitionImpl("this", dataTypeFor(body.cls) ?: Undefined4DataType.dataType, null)
                val otherParams =
                    body.params.mapIndexed { i, p ->
                        ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: Undefined4DataType.dataType, null)
                    }
                fd.setArguments(*(listOf(thisParam) + otherParams).toTypedArray())
                fd
            }

            is TypeDecl.XRef -> {
                sink.log("xref-stub", "Forward ref to '${body.tagName}'; materialising stub")
                placeholder
            }

            is TypeDecl.Ref -> {
                // Same cascade as dataTypeFor: byId -> placeholders -> rawByIdSnapshot -> classify.
                byId[body.id]
                    ?: placeholders[body.id]
                    ?: rawByIdSnapshot[body.id]?.let { raw ->
                        makePlaceholder(raw.body, CategoryPath("/stabs"), raw.name)
                            .also { placeholders[body.id] = it }
                    }
                    ?: run {
                        val refKey = "(${body.id.cu},${body.id.n})"
                        val includeCtx = includeContextsByFile[ast.cuFile]
                        val knownFileNums = includeCtx?.getAllFileNums() ?: emptySet()
                        // Truly-missing classifier: rawByIdSnapshot already exhausted above.
                        val knownTypeIds = emptySet<TypeId>()

                        val classification =
                            ResolverDecision.classifyRef(
                                body.id,
                                ast.id.cu,
                                knownTypeIds,
                                knownFileNums,
                            )

                        sink.log("dangling-ref", "Dangling ref to $refKey in '${ast.name}' [${classification.tag}]")
                        diagnostics.recordUnresolvedRef(refKey, ast.name, ast.cuFile)
                        diagnostics.inc("dangling-ref-${classification.tag}")

                        Undefined4DataType.dataType
                    }
            }
        }

    private fun registerWithConflict(
        dt: DataType,
        name: String,
        hash: ContentHash,
        category: CategoryPath,
    ): DataType {
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
        // Fall back to renaming: find a free _N slot
        // EXCEPT for Structures in conflict: drop them entirely (no _N renaming)
        if (dt is Structure && existing is Structure) {
            // Already tried merge and it failed; was logged via recordDedup in tryExecuteMerge
            return existing
        }
        var n = (conflictCount[name] ?: 1) + 1
        while (true) {
            val candidate = "${name}_$n"
            if (dtm.getDataType(category, candidate) == null) break
            n++
            if (n > 1000) error("cannot allocate conflict suffix for '$name'")
        }
        conflictCount[name] = n
        // Clone and rename
        val copy = dt.copy(dtm)
        copy.name = "${name}_$n"
        sink.log("type-conflict", "Two definitions of '$name' with different bodies; second renamed to '${name}_$n'")
        diagnostics.recordDedup(kind = "rename", name = name, detail = "renamed-to-${name}_$n")
        byPath[category to "${name}_$n"] = hash
        return dtm.addDataType(copy, DataTypeConflictHandler.KEEP_HANDLER)
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
        incomingHash: ContentHash,
    ): DataType? {
        val existingComp = existing.toComponentRecords()
        val incomingComp = incoming.toComponentRecords()
        val result = StructuralDiff.diff(existingComp, existing.length, incomingComp, incoming.length)

        return when (result) {
            StructDiffResult.Identical -> {
                // Same structure layout, already idempotent
                existing
            }

            is StructDiffResult.GapMergeable -> {
                // Execute the merge plan
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
                            sink.log(
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
                sink.log("dedup-merged", "$name: ${result.mergePlan.size} fields merged")
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
        for ((key, hash) in byPath) {
            if (hash != null && key.second == simpleName) {
                candidates.add(key)
            }
        }
        return when {
            candidates.isEmpty() -> null
            candidates.size == 1 -> dtm.getDataType(candidates[0].first, candidates[0].second)
            else -> {
                // Multiple matches: ambiguous. Log and count.
                sink.log("demangler-ambiguous", "Multiple matches for '$simpleName': $candidates")
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
fun computeGaps(
    componentRecords: List<Pair<String, Pair<Int, Int>>>,
    totalLengthBytes: Int,
): List<GapRecord> {
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
            val gapStart = currEnd
            val gapLength = nextOffset - currEnd
            gaps.add(
                GapRecord(
                    offsetBits = (gapStart * 8).toLong(),
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
