package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.GapRecord
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.LocalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.isXRefTarget
import ghistabs.runTransaction

class TypeRegistry(
    private val dtm: DataTypeManager,
    private val sink: DiagnosticSink,
    private val diagnostics: StabsDiagnostics,
    private val harvest: Harvest,
    private val resolver: TypeResolver,
) : DiagnosticSink by sink {
    private val byId = mutableMapOf<GlobalTypeId, DataType>()
    private val placeholders = mutableMapOf<GlobalTypeId, DataType>()

    /**
     * DataTypes that originated as an unresolved XRef placeholder. An XRef stub
     * is benign when wrapped in a `Pointer→<stub>` or `Reference→<stub>` — gcc
     * deliberately emits the forward decl in that case and `void*` semantics
     * survive in the listing. It's a real layout loss when one appears as a
     * struct field, base class, or array element — those use sites are caught
     * by [recordXRefStubAt] and emitted as their own degradation bucket.
     */
    private val xrefStubs = mutableSetOf<DataType>()

    private fun recordXRefStubAt(useSite: String, where: String, dt: DataType) {
        if (dt in xrefStubs) {
            diagnostics.recordDegradation("xref-stub-in-$useSite", where, "type=${dt.name}")
        }
    }

    fun tryGetExisting(gId: GlobalTypeId) = byId[gId] ?: placeholders[gId] ?: harvest.getType(gId)?.let { raw ->
        // Primitives (Range, Builtin, Float, …) resolve directly via BuiltinTable.
        // Without this, the `else` branch in makePlaceholder creates a zero-size
        // StructureDataType as a stand-in. When that stub later appears as a field
        // type inside a real struct, Ghidra auto-registers it as a StructureDB,
        // shadowing the properly-named TypedefDB added later by the typedef loop.
        BuiltinTable.resolve(raw.body)?.also { byId[gId] = it }
            ?: makePlaceholder(raw, CategoryPath("/stabs")).also { placeholders[gId] = it }
    }

    /**
     * The materialised DataType for a TypeAst id, as registered by [materialiseAll].
     * Returns null if the id was never registered (e.g. non-registerable typeAst that
     * went through the on-demand `resolve()` path). Prefer this over `dtm.getDataType`
     * — it skips the DTM round-trip and is the authoritative source for the
     * `(category, name)` slot's current DataType.
     */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]

    /**
     * Walk the placeholders map at end-of-import and log every Struct/Union
     * typeAst whose body never made it into the DTM as a non-empty aggregate.
     * These are the source of downstream cascades like `merge-failed`
     * "Offset 0 beyond end of structure" and bogus 1-byte fields in the
     * listing. Naming them at the source makes the cause findable.
     *
     * Only Struct/Union typeAsts are considered: [makePlaceholder] hands out a
     * throwaway empty Structure stub for non-aggregate bodies (Range, Enum,
     * FunctionT, …), but those stubs are never registered in the DTM —
     * `materialiseBody` returns the real DataType directly. Reporting those
     * would be noise, not a bug.
     */
    fun reportSurvivingPlaceholders() {
        for ((id, placeholder) in placeholders) {
            val ast = harvest.getType(id) ?: continue
            if (ast.body !is TypeDecl.Struct) continue
            val composite = placeholder as? Composite ?: continue
            // Empty C++ structs (e.g. tag/trait types) have sizeBytes=1 and no
            // source fields. Ghidra fills the byte with Undefined1 padding, which
            // would otherwise show up as `placeholder-undefined-fields`. That's
            // the correct representation of an empty struct, not a degradation.
            val sourceHasNoMembers =
                ast.body.fields.none { !it.isStatic } && ast.body.bases.isEmpty()
            val tag = when {
                composite.numComponents == 0 && !sourceHasNoMembers -> "placeholder-unresolved"
                composite.allComponentsUndefined() && !sourceHasNoMembers -> "placeholder-undefined-fields"
                else -> continue
            }
            diagnostics.recordDegradation(
                tag,
                "${composite.categoryPath}/${composite.name}",
                when (tag) {
                    "placeholder-unresolved" -> "never had its body materialised (id=$id)"
                    else -> "materialised but every field fell back to Undefined (id=$id)"
                },
            )
        }
    }

    /**
     * A struct "filled with undefined" is one whose every component's data type is in the
     * `UndefinedNDataType` family — i.e. every field's Ref or XRef failed to resolve and
     * the materialiser used the `Undefined4` fallback. From the user's point of view this
     * is no better than an empty placeholder; flagging it separately distinguishes
     * "body never ran" from "body ran but couldn't bind any field type".
     */
    private fun Composite.allComponentsUndefined(): Boolean {
        if (numComponents == 0) return false
        return components.all { it.dataType.name.startsWith("undefined") }
    }

    fun materialiseAll() {
        // Two-phase walk driven by resolver.byCanonicalKey:
        //  1. For each CanonicalGroup, materialise the winner once into its (cat, name)
        //     slot and alias every member's id to the resulting DataType.
        //  2. Handle non-registerable top-level typeAsts (XRef-aliased helpers,
        //     FunctionT, Method, …) via the legacy resolve() path — they need byId
        //     entries for Ref resolution but never occupy a stable Ghidra slot.
        dtm.runTransaction("ghidra-stabs build types") {
            val memberToWinner: Map<GlobalTypeId, TypeAst> = buildMap {
                for (group in resolver.byCanonicalKey.values) {
                    for (m in group.members) put(m, group.ast)
                }
            }
            val winnerCategory: Map<GlobalTypeId, CategoryPath> = buildMap {
                for (group in resolver.byCanonicalKey.values) put(group.ast.id, group.key.category)
            }

            // Pre-seed placeholders for every member id so Ref(id) cycle-breaks during
            // body materialisation. Struct/Union placeholders go into the DTM up-front
            // so later in-place mutations land on the DTM-resident object.
            for (group in resolver.byCanonicalKey.values) {
                val winner = group.ast
                val raw = makePlaceholder(winner, group.key.category)
                val placeholder = if (winner.body is TypeDecl.Struct) {
                    dtm.addDataType(raw, DataTypeConflictHandler.KEEP_HANDLER)
                } else {
                    raw
                }
                for (m in group.members) placeholders.putIfAbsent(m, placeholder)
            }

            // Materialise winners.
            for ((winnerId, category) in winnerCategory) {
                val winner = harvest.getType(winnerId) ?: continue
                val placeholder = placeholders[winnerId]!!
                val materialised = materialiseBody(winner, category, placeholder)
                val canonical = if (materialised === placeholder) {
                    placeholder
                } else {
                    dtm.addDataType(materialised, DataTypeConflictHandler.KEEP_HANDLER)
                }
                byId[winnerId] = canonical
            }
            // Alias members to their winner's DataType.
            for ((memberId, winner) in memberToWinner) {
                byId[winner.id]?.let { byId.putIfAbsent(memberId, it) }
            }

            // Materialise named primitive typedefs (Range, Builtin, Float, etc.).
            // These don't qualify as XRefTarget so they're absent from byCanonicalKey,
            // but stabs assigns them names ("unsigned int", "char", …) that should
            // appear in the DTM as typedef aliases for the corresponding Ghidra builtins.
            // Group by ghidraName to emit exactly one typedef per logical primitive name.
            harvest.typeAsts.values
                .filter { it.name != null && !it.body.isXRefTarget }
                .groupBy { it.ghidraName }
                .forEach { (ghidraName, asts) ->
                    val body = asts.first().body
                    val resolved = BuiltinTable.resolve(body) ?: return@forEach
                    val typedef = dtm.addDataType(
                        TypedefDataType(CategoryPath.ROOT, ghidraName, resolved, dtm),
                        DataTypeConflictHandler.KEEP_HANDLER,
                    )
                    for (ast in asts) byId.putIfAbsent(ast.id, typedef)
                }

            // Non-registerable top-level typeAsts (XRef body, FunctionT, Method, …)
            for (ast in harvest.typeAsts.values) {
                if (ast.id in byId) continue
                resolve(ast)
            }
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

        is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin -> {
            BuiltinTable.resolve(decl)
        }

        is TypeDecl.Pointer -> PointerDataType(
            dataTypeFor(decl.pointee) ?: undef("pointer-pointee", "(anon)", decl.pointee),
            4,
            dtm,
        )

        is TypeDecl.Reference -> PointerDataType(
            dataTypeFor(decl.referent) ?: undef("reference-referent", "(anon)", decl.referent),
            4,
            dtm,
        )

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
                ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: undef("functionT-param", "(anon)[$i]", p), null)
            }.toTypedArray()
            fd.setArguments(*params)
            fd
        }

        // XRef → canonical TypeAst by (kind, tagName), then look up the
        // materialised DataType by its id. Unified across struct / union
        // / class / enum (the old code asymmetrically asked dataTypeFor()
        // for the resolved body, which the aggregate branch always
        // returns null for — silently dropping every non-struct XRef).
        is TypeDecl.XRef -> resolver.byXRef(decl)?.let { tryGetExisting(it.id) }

        // Aggregate bodies — never referenced directly; only meaningful via TypeId.
        // See kdoc above.
        is TypeDecl.Struct, is TypeDecl.Enum, is TypeDecl.Method -> {
            log("referenced-aggregate", "asked for ref to $decl")
            null
        }
    }

    /**
     * Unified fallback for every `dataTypeFor(...) ?: Undefined4` site. Returns
     * `Undefined4` and records a degradation so the end-of-run dump enumerates
     * every silent coverage loss. [category] is the bucket (e.g. `field-type`,
     * `body-pointer-pointee`); [where] is the qualified offending location
     * (e.g. `Foo.bar`, `Cls::method[2]`); the decl is captured as detail.
     */
    private fun undef(category: String, where: String, decl: TypeDecl<GlobalTypeId>): DataType {
        diagnostics.recordDegradation(category, where, decl.toString())
        return Undefined4DataType.dataType
    }

    private fun makePlaceholder(ast: TypeAst, category: CategoryPath, reason: String = "fwd-decl"): DataType {
        val dt = when (ast.body) {
            is TypeDecl.Struct if (ast.body.kind == AggrKind.UNION) -> UnionDataType(category, ast.ghidraName, dtm)
            is TypeDecl.Struct -> StructureDataType(category, ast.ghidraName, ast.body.sizeBytes.toInt(), dtm)
            else -> StructureDataType(category, ast.ghidraName, 0, dtm)
        }
        diagnostics.recordPlaceholder(ast.nameOrId, category.toString(), reason)
        return dt
    }

    /**
     * Materialise a non-registerable top-level typeAst (XRef alias, FunctionT, Method).
     * Registerable bodies (Struct/Enum) are handled directly in [materialiseAll] via
     * `resolver.byCanonicalKey`.
     */
    private fun resolve(ast: TypeAst): DataType {
        if (ast.body is TypeDecl.XRef) {
            resolver.byXRef(ast.body)?.let { canonical ->
                val dt = byId[canonical.id] ?: resolve(canonical)
                byId[ast.id] = dt
                return dt
            }
        }
        val placeholder = placeholders.getOrPut(ast.id) {
            makePlaceholder(ast, CategoryPath("/stabs"), "ref-stub")
        }
        val materialised = materialiseBody(ast, CategoryPath("/stabs"), placeholder)
        byId.putIfAbsent(ast.id, materialised)
        return materialised
    }

    private fun materialiseBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType =
        when (val body = ast.body) {
            is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin ->
                BuiltinTable.resolve(body) ?: placeholder

            is TypeDecl.Pointer -> PointerDataType(
                dataTypeFor(body.pointee) ?: undef("body-pointer-pointee", ast.nameOrId, body.pointee),
                4,
                dtm,
            )

            is TypeDecl.Reference -> PointerDataType(
                dataTypeFor(body.referent) ?: undef("body-reference-referent", ast.nameOrId, body.referent),
                4,
                dtm,
            )

            is TypeDecl.Const -> dataTypeFor(body.inner) ?: placeholder

            is TypeDecl.Volatile -> dataTypeFor(body.inner) ?: placeholder

            // Look up the INNER (decl.id) typeAst — gcc emits anonymous nested aggregates
            // (e.g. C `struct { ... }` member types in box2d) as InlineDef wrappers around
            // an aggregate body. `dataTypeFor(body)` dispatches to the InlineDef case which
            // calls `tryGetExisting(body.id)` first; that picks up the harvested typeAst
            // for the inner aggregate instead of falling through to the
            // `referenced-aggregate` branch that returns null. Avoids 535 silent
            // null-resolutions on box2d's nested-struct fields.
            is TypeDecl.InlineDef -> dataTypeFor(body)?.also {
                byId[body.id] = it
            } ?: placeholder

            is TypeDecl.Array -> {
                val elem = dataTypeFor(body.element) ?: run {
                    diagnostics.recordDegradation("array-element", ast.nameOrId, body.element.toString())
                    ByteDataType.dataType
                }
                recordXRefStubAt("array-element", ast.nameOrId, elem)
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
                            recordXRefStubAt("base", "${ast.nameOrId}@+$offsetBytes", dt)
                            dataTypeByOffset[offsetBytes] = dt
                            resolvedBaseInfo[offsetBytes] = ResolvedBase(dt.name, dt.length)
                            continue
                        }
                        // Synthesise a placeholder of the size implied by layout.
                        val nextOffset =
                            sortedBaseOffsetsBytes.firstOrNull { it > offsetBytes } ?: firstFieldOffsetBytes
                        val inferredSize = nextOffset - offsetBytes
                        if (inferredSize <= 0) {
                            diagnostics.recordDegradation(
                                "base-skipped-zero-size",
                                "${ast.nameOrId}@+$offsetBytes",
                                "cannot infer size",
                            )
                            continue
                        }
                        val synthName = "unknown_$offsetBytes"
                        val synthDt = ArrayDataType(Undefined1DataType.dataType, inferredSize, 1)
                        dataTypeByOffset[offsetBytes] = synthDt
                        resolvedBaseInfo[offsetBytes] = ResolvedBase(synthName, inferredSize)
                        diagnostics.recordDegradation(
                            "base-synthesized",
                            "${ast.nameOrId}@+$offsetBytes",
                            "Ref unresolved, synthesised $inferredSize-byte placeholder",
                        )
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
                            diagnostics.recordDegradation(
                                "base-layout-failed",
                                "${ast.nameOrId}::${op.baseSimpleName}",
                                e.message,
                            )
                            diagnostics.inc("inheritance-failed")
                        }
                    }
                }

                // Compute polymorphic base for inherited vfptr gating
                val polyBase = ClassBuilderHelpers(resolver).firstPolymorphicBase(body)

                // Pre-compute base-occupied offset set so a parser-emitted vptr that lands
                // inside a base subobject is filtered out — regardless of whether we could
                // prove the base polymorphic. When the base is unresolved (synthesised
                // _base_unknown_*) `firstPolymorphicBase` returns null, but the stab still
                // emitted a _vptr$Class at the base's offset, and gcc only does that when
                // the base owns the vfptr. Trying to apply our vptr there just collides
                // with the synthesised base — see bouniaf → ios_base cascade.
                val baseOffsets = body.bases.map { it.offsetBits }.toSet()

                // Existing field loop (unchanged).
                for (field in body.fields) {
                    if (field.isStatic) continue // Skip static fields

                    // Skip parser-emitted _vptr$<class> field if inherited from polymorphic base
                    val isParserEmittedVptr =
                        field.name.startsWith("_vptr$") || field.name.startsWith("_vptr.") || field.name == "_vptr"
                    if (
                        isParserEmittedVptr &&
                        (
                            (polyBase != null && field.offsetBits == polyBase.offsetBits) ||
                                field.offsetBits in baseOffsets
                            )
                    ) {
                        // Inherited vfptr — the _base_<Base> (resolved or synthesised) at
                        // that offset already carries it. Skip.
                        diagnostics.inc("vptr-skipped-inherited")
                        continue
                    }

                    val resolvedFt = dataTypeFor(field.type)
                    val ft = resolvedFt
                        ?: undef("field-type", "${ast.ghidraName}.${field.name}", field.type)
                    if (resolvedFt != null && resolvedFt.name.startsWith("undefined")) {
                        diagnostics.recordDegradation(
                            "field-resolved-to-undefined",
                            "${ast.ghidraName}.${field.name}",
                            "type=${resolvedFt.name} from ${field.type}",
                        )
                    }
                    if (resolvedFt != null) {
                        recordXRefStubAt("field", "${ast.ghidraName}.${field.name}", resolvedFt)
                    }
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
                        diagnostics.recordDegradation(
                            "field-dropped",
                            "${ast.nameOrId}.${field.name}",
                            e.message,
                        )
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
                fd.returnType = dataTypeFor(body.ret) ?: run {
                    diagnostics.recordDegradation("functionT-ret", ast.ghidraName, body.ret.toString())
                    VoidDataType()
                }
                val params = body.params.mapIndexed { i, p ->
                    ParameterDefinitionImpl(
                        "arg$i",
                        dataTypeFor(p) ?: undef("functionT-param", "${ast.ghidraName}[$i]", p),
                        null,
                    )
                }.toTypedArray()
                fd.setArguments(*params)
                fd
            }

            is TypeDecl.Method -> {
                val fd = FunctionDefinitionDataType(category, ast.ghidraName, dtm)
                fd.returnType = dataTypeFor(body.ret) ?: run {
                    diagnostics.recordDegradation("method-ret", ast.ghidraName, body.ret.toString())
                    VoidDataType()
                }
                val thisParam = ParameterDefinitionImpl(
                    "this",
                    dataTypeFor(body.cls) ?: undef("method-this-cls", ast.ghidraName, body.cls),
                    null,
                )
                val otherParams =
                    body.params.mapIndexed { i, p ->
                        ParameterDefinitionImpl(
                            "arg$i",
                            dataTypeFor(p) ?: undef("method-param", "${ast.ghidraName}[$i]", p),
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
                // Resolver records the degradation itself (with the right
                // bucket by reason) when the lookup fails — we just alias or
                // fall back to the placeholder.
                (resolver.lookupByXRef(body) as? TypeResolver.XRefLookup.Resolved)
                    ?.ast?.let { canonical -> tryGetExisting(canonical.id)?.also { byId[ast.id] = it } }
                    ?: placeholder.also { xrefStubs.add(it) }
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
                diagnostics.recordDegradation(
                    "dangling-ref",
                    ast.nameOrId,
                    "ref to ${body.id} from ${ast.source}",
                )
                Undefined4DataType.dataType
            }
        }

    /**
     * Find a DataType by simple ghidraName (no path), used by DemanglerReplacer.
     * Walks `resolver.byCanonicalKey` — the authoritative (category, name) view —
     * and returns null on ambiguity (no heuristic guess).
     */
    fun findByName(simpleName: String): DataType? {
        val candidates = resolver.byCanonicalKey.keys.filter { it.name == simpleName }
        return when {
            candidates.isEmpty() -> null

            candidates.size == 1 -> dtm.getDataType(candidates[0].category, candidates[0].name)

            else -> {
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
