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

    /** XRef placeholders flagged at use-sites where a forward decl is a real layout loss. */
    private val xrefStubs = mutableSetOf<DataType>()

    /** Id-less DTM writes (typedef aliases, vftable composites, slot FDs), keyed for [findByName]. */
    private val extrasByName = LinkedHashMap<String, LinkedHashSet<DataType>>()

    /** Resolve [dt] into the DTM and remember it (no TypeId binding). For id-less writes. */
    fun register(dt: DataType): DataType {
        val resolved = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
        extrasByName.getOrPut(resolved.name) { LinkedHashSet() }.add(resolved)
        return resolved
    }

    /** Resolve [dt] into the DTM and cache it as the canonical type for [id]. */
    fun register(dt: DataType, id: GlobalTypeId): DataType {
        val resolved = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
        byId[id] = resolved
        return resolved
    }

    /** Get-or-create a DTM-resident DataType at `(category, name)` of type [T]. */
    inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T {
        (dtmLookup(category, name) as? T)?.let { return it }
        return register(build()) as T
    }

    @PublishedApi
    internal fun dtmLookup(category: CategoryPath, name: String): DataType? = dtm.getDataType(category, name)

    /** Every DataType this importer materialised or registered. */
    fun allCreatedDataTypes(): Set<DataType> {
        val result = LinkedHashSet<DataType>()
        result.addAll(byId.values)
        for (bucket in extrasByName.values) result.addAll(bucket)
        return result
    }

    private fun recordXRefStubAt(useSite: String, at: String, dt: DataType) {
        if (dt in xrefStubs) {
            diagnostics.recordDegradation("xref-stub-in-$useSite", at, "type=${dt.name}")
        }
    }

    /** Look up an already-materialised type by id; for Struct/Union, seed an empty placeholder if absent. */
    fun tryGetExisting(gId: GlobalTypeId) = byId[gId] ?: placeholders[gId] ?: harvest.getType(gId)?.let { raw ->
        BuiltinTable.resolve(raw.body)?.also { byId[gId] = it }
            ?: if (raw.body is TypeDecl.Struct) {
                // Cycle-break: self-referential field Refs need a placeholder before materialiseBody runs.
                makePlaceholder(raw, CategoryPath("/stabs")).also { placeholders[gId] = it }
            } else {
                resolve(raw)
            }
    }

    /** Materialised DataType for [id], or null if [materialiseAll] never ran for it. */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]

    /** Log Struct/Union placeholders that never got materialised — flag the source of downstream merge cascades. */
    fun reportSurvivingPlaceholders() {
        for ((id, placeholder) in placeholders) {
            val ast = harvest.getType(id) ?: continue
            if (ast.body !is TypeDecl.Struct) continue
            val composite = placeholder as? Composite ?: continue
            // Skip empty C++ tag/trait structs — their Undefined1 padding is the correct representation.
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

    /** True when every field's type resolved to the `UndefinedN` fallback. */
    private fun Composite.allComponentsUndefined(): Boolean {
        if (numComponents == 0) return false
        return components.all { it.dataType.name.startsWith("undefined") }
    }

    /**
     * Two-phase build:
     *  1. For each [resolver.byCanonicalKey] group, materialise the winner once and alias members to it.
     *  2. Resolve named primitive typedefs, then handle non-registerable top-level TypeAsts via [resolve].
     */
    fun materialiseAll() {
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
                    // Add to DTM up-front so later in-place mutations land on
                    // the DTM-resident object. byId is set below by the winner
                    // materialiser; here we just need the DTM-resolved handle.
                    register(raw)
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
                if (materialised === placeholder) {
                    // Pre-seeded into DTM above (for Struct) or kept in-memory
                    // (for non-Struct, which materialiseBody handled directly).
                    byId[winnerId] = placeholder
                } else {
                    register(materialised, winnerId)
                }
            }
            // Alias members to their winner's DataType.
            for ((memberId, winner) in memberToWinner) {
                byId[winner.id]?.let { byId.putIfAbsent(memberId, it) }
            }

            // Named primitive typedefs (Range/Builtin/Float/…): emit one typedef per ghidraName.
            harvest.typeAsts.values
                .filter { it.name != null && !it.body.isXRefTarget }
                .groupBy { it.ghidraName }
                .forEach { (ghidraName, asts) ->
                    // Resolve per-ast for byId so cross-CU size disagreements (e.g. bool:1B vs 4B) stay distinct.
                    for (ast in asts) {
                        val resolved = BuiltinTable.resolve(ast.body) ?: dataTypeFor(ast.body) ?: continue
                        byId.putIfAbsent(ast.id, resolved)
                    }
                    val firstBody = asts.first().body
                    val typedefTarget = BuiltinTable.resolve(firstBody) ?: dataTypeFor(firstBody) ?: return@forEach
                    val category = if (BuiltinTable.resolve(firstBody) != null) {
                        CategoryPath.ROOT
                    } else {
                        CategoryPath("/stabs")
                    }
                    register(TypedefDataType(category, ghidraName, typedefTarget, dtm))
                }

            for (ast in harvest.typeAsts.values) {
                if (ast.id in byId) continue
                resolve(ast)
            }
        }
    }

    /** gcc/gdb: `Ref(self.id)` encodes void (return type / end-of-args terminator). */
    private fun isVoidSelfRef(id: GlobalTypeId): Boolean {
        val ast = harvest.getType(id) ?: return false
        val body = ast.body
        return body is TypeDecl.Ref && body.id == id
    }

    /**
     * Resolve a [TypeDecl] encountered inside another type (field, pointee, base, …) to a Ghidra DataType.
     * Refs/InlineDefs go via [byId]/placeholders/harvest (cycle-safe); aggregate bodies have no defined
     * lookup — only the materialiser holds their (category, name) slot.
     */
    fun dataTypeFor(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        is TypeDecl.Ref -> tryGetExisting(decl.id)
            ?: if (isVoidSelfRef(decl.id)) VoidDataType() else null

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
            dtm.dataOrganization.pointerSize,
            dtm,
        )

        is TypeDecl.Reference -> PointerDataType(
            dataTypeFor(decl.referent) ?: undef("reference-referent", "(anon)", decl.referent),
            dtm.dataOrganization.pointerSize,
            dtm,
        )

        is TypeDecl.Const -> dataTypeFor(decl.inner)

        is TypeDecl.Volatile -> dataTypeFor(decl.inner)

        is TypeDecl.Array -> {
            // For arrays of unresolved element types (e.g. globals whose
            // `byte` (not Undefined1) — Undefined1 is type-equivalent to autoanalysis padding and gets re-coalesced.
            val elem = dataTypeFor(decl.element) ?: ByteDataType.dataType
            // Length: explicit decl.length, else indexType.Range size, else 1.
            val rangeLen = (decl.indexType as? TypeDecl.Range)
                ?.let { it.max - it.min + 1 }
                ?.takeIf { it > 0 }
            val numElements = (decl.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
            ArrayDataType(elem, numElements, elem.length)
        }

        is TypeDecl.FunctionT -> buildFunctionDefinition(
            category = CategoryPath("/stabs/unnamed"),
            name = "FUNCTION_${decl.hashCode()}",
            ret = decl.ret,
            params = decl.params,
            at = "FunctionT(anon)",
        )

        is TypeDecl.XRef -> resolver.byXRef(decl)?.let { tryGetExisting(it.id) }

        is TypeDecl.Struct, is TypeDecl.Enum, is TypeDecl.Method -> {
            log("referenced-aggregate", "asked for ref to $decl")
            null
        }
    }

    /**
     * Build a [FunctionDefinitionDataType] from stab-level types. Shared by FunctionT/Method materialisation
     * and the vftable-slot builder. Not added to the DTM — caller decides.
     */
    fun buildFunctionDefinition(
        category: CategoryPath,
        name: String,
        ret: TypeDecl<GlobalTypeId>,
        params: List<TypeDecl<GlobalTypeId>>,
        thisType: DataType? = null,
        callingConvention: String? = null,
        at: String = name,
    ): FunctionDefinitionDataType {
        val fd = FunctionDefinitionDataType(category, name, dtm)
        fd.returnType = dataTypeFor(ret) ?: run {
            diagnostics.recordDegradation("function-ret-untyped", at, ret.toString())
            VoidDataType()
        }
        // Drop gcc's trailing void sentinel (mid-list voids → Undefined4).
        val effectiveParams = if (params.isNotEmpty() && dataTypeFor(params.last()) is VoidDataType) {
            params.dropLast(1)
        } else {
            params
        }
        // gcc's `#` method form puts `this` as params[0]; just name it.
        val argDefs = effectiveParams.mapIndexed { i, p ->
            val resolved = dataTypeFor(p) ?: undef("function-param", "$at[$i]", p)
            val safe = if (resolved is VoidDataType) Undefined4DataType.dataType else resolved
            ParameterDefinitionImpl(if (i == 0 && thisType != null) "this" else "arg$i", safe, null)
        }
        fd.setArguments(*argDefs.toTypedArray())
        // Calling conventions that aren't known to this program's CompilerSpec
        // (e.g. __thiscall on x86-64 ELF) cause setCallingConvention to throw
        // when the FD is later attached to the DTM. Validate up-front against
        // the DTM's known list and skip silently when unsupported — the FD
        // stays at the default convention.
        // Skip silently when the cspec doesn't know the convention (e.g. __thiscall on x86-64 ELF).
        if (callingConvention != null && callingConvention in dtm.knownCallingConventionNames) {
            runCatching { fd.setCallingConvention(callingConvention) }
        }
        return fd
    }

    /** Fall back to Undefined4 and record a degradation under [category] / [at]. */
    private fun undef(category: String, at: String, decl: TypeDecl<GlobalTypeId>): DataType {
        diagnostics.recordDegradation(category, at, decl.toString())
        return Undefined4DataType.dataType
    }

    /** Empty-shell placeholder for an aggregate body, so self-referential Refs can cycle-break. */
    private fun makePlaceholder(ast: TypeAst, category: CategoryPath, reason: String = "fwd-decl"): DataType {
        val dt = when (ast.body) {
            is TypeDecl.Struct if (ast.body.kind == AggrKind.UNION) -> UnionDataType(category, ast.ghidraName, dtm)
            is TypeDecl.Struct -> {
                val sz = usefulStructSize(ast.body)
                recordTruncation(ast, ast.body.sizeBytes.toInt(), sz)
                StructureDataType(category, ast.ghidraName, sz, dtm)
            }
            // Must be EnumDataType — an empty Structure here gets adopted by replaceAtOffset
            // and then collides with the real Enum when the winner registers.
            is TypeDecl.Enum -> EnumDataType(category, ast.ghidraName, 4, dtm)
            else -> StructureDataType(category, ast.ghidraName, 0, dtm)
        }
        diagnostics.recordPlaceholder(ast.nameOrId, category.toString(), reason)
        return dt
    }

    /**
     * Effective struct size — the last byte we have a field description for. Trims gcc's
     * over-allocated `sizeBytes` (e.g. CLexStream s328 with fields ending at 192) when the
     * gap exceeds the largest field size, since legitimate trailing padding is bounded by
     * (alignment - 1) ≤ maxFieldSize - 1.
     */
    private fun usefulStructSize(body: TypeDecl.Struct<GlobalTypeId>): Int {
        val nonStatic = body.fields.filter { !it.isStatic }
        if (nonStatic.isEmpty()) return body.sizeBytes.toInt()
        val fieldEnd = nonStatic.maxOf { ((it.offsetBits + it.sizeBits + 7) / 8).toInt() }
        val claimed = body.sizeBytes.toInt()
        val maxFieldSize = nonStatic.maxOf { ((it.sizeBits + 7) / 8).toInt() }
        return if (claimed - fieldEnd > maxFieldSize) fieldEnd else claimed
    }

    private fun recordTruncation(ast: TypeAst, originalBytes: Int, truncatedBytes: Int) {
        if (originalBytes <= truncatedBytes) return
        diagnostics.recordDegradation(
            "struct-truncated",
            ast.ghidraName,
            "stab claims $originalBytes bytes, last described byte $truncatedBytes; trimmed ${originalBytes - truncatedBytes}",
        )
    }

    /** Materialise a non-registerable top-level TypeAst (XRef alias, FunctionT, Method, self-Ref-void). */
    private fun resolve(ast: TypeAst): DataType {
        if (ast.body is TypeDecl.XRef) {
            resolver.byXRef(ast.body)?.let { canonical ->
                val dt = byId[canonical.id] ?: resolve(canonical)
                byId[ast.id] = dt
                return dt
            }
        }
        if (ast.body is TypeDecl.Ref && ast.body.id == ast.id) {
            val void = VoidDataType()
            byId[ast.id] = void
            return void
        }
        val placeholder = placeholders.getOrPut(ast.id) {
            makePlaceholder(ast, CategoryPath("/stabs"), "ref-stub")
        }
        val materialised = materialiseBody(ast, CategoryPath("/stabs"), placeholder)
        byId.putIfAbsent(ast.id, materialised)
        return materialised
    }

    /**
     * Size enums per gdb's `stabsread.c::read_enum_type`: `sizeof(int)` unless gcc emits an
     * explicit `@s<bits>` (`-fshort-enums`). bool doesn't reach this path — it comes through
     * BuiltinTable slot -16.
     */
    private fun materialiseEnum(
        ast: TypeAst,
        category: CategoryPath,
        body: TypeDecl.Enum<GlobalTypeId>,
        explicitSizeBits: Int?,
    ): DataType {
        val sizeBytes = if (explicitSizeBits != null) (explicitSizeBits + 7) / 8 else 4
        val e = EnumDataType(category, ast.ghidraName, sizeBytes, dtm)
        for ((mname, mval) in body.members) e.add(mname, mval)
        return e
    }

    private fun materialiseBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType =
        when (val body = ast.body) {
            is TypeDecl.Pointer -> PointerDataType(
                dataTypeFor(body.pointee) ?: undef("body-pointer-pointee", ast.nameOrId, body.pointee),
                dtm.dataOrganization.pointerSize,
                dtm,
            )

            is TypeDecl.Reference -> PointerDataType(
                dataTypeFor(body.referent) ?: undef("body-reference-referent", ast.nameOrId, body.referent),
                dtm.dataOrganization.pointerSize,
                dtm,
            )

            is TypeDecl.Const -> dataTypeFor(body.inner) ?: placeholder

            is TypeDecl.Volatile -> dataTypeFor(body.inner) ?: placeholder

            // Resolve InlineDef via its inner id — anonymous nested aggregates would otherwise
            // hit the `referenced-aggregate` null branch.
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
                // ArrayDataType.validate needs element.length > 0; FunctionDefinition reports 0.
                val safeElem = if (elem.length < 1) {
                    diagnostics.recordDegradation(
                        "array-element-unsized",
                        ast.nameOrId,
                        "${elem::class.simpleName} has length ${elem.length}; substituted Undefined4",
                    )
                    Undefined4DataType.dataType
                } else {
                    elem
                }
                ArrayDataType(safeElem, numElements, safeElem.length)
            }

            is TypeDecl.Enum -> materialiseEnum(ast, category, body, explicitSizeBits = null)

            // `@s<bits>;e...;` — explicit size attribute (-fshort-enums etc.).
            is TypeDecl.WithSizeAttr if body.inner is TypeDecl.Enum ->
                materialiseEnum(ast, category, body.inner, explicitSizeBits = body.sizeBits)

            is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin ->
                BuiltinTable.resolve(body) ?: placeholder

            is TypeDecl.Struct -> {
                val struct: Composite = if (body.kind == AggrKind.UNION) {
                    placeholder as Union
                } else {
                    placeholder as Structure
                }

                if (struct is Structure) {
                    // Infer each base's subobject size from the gap to the next base or first field —
                    // gcc's inheritance line doesn't transmit it (CSymLexStream sees CLexStream as
                    // 192 bytes even though canonical CLexStream is 328 from a richer CU).
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
                        val nextOffset =
                            sortedBaseOffsetsBytes.firstOrNull { it > offsetBytes } ?: firstFieldOffsetBytes
                        val gap = nextOffset - offsetBytes

                        // Ghidra forces length>=1 on empty Composites; check isZeroLength for the truth.
                        if (dt != null && !dt.isZeroLength && dt.length > 0 && dt.length <= gap) {
                            dataTypeByOffset[offsetBytes] = dt
                            resolvedBaseInfo[offsetBytes] = ResolvedBase(dt.name, dt.length)
                            continue
                        }

                        // gap==0 → empty base optimization (resolved or unresolved); skip insertion.
                        if (gap <= 0) {
                            if (dt == null) {
                                diagnostics.inc("base-empty-ebo-inferred")
                            } else {
                                diagnostics.inc("base-empty-ebo")
                            }
                            continue
                        }
                        // Unresolved or oversized → synthesise a gap-sized placeholder.
                        val synthName = "unknown_$offsetBytes"
                        val synthDt = ArrayDataType(Undefined1DataType.dataType, gap, 1)
                        dataTypeByOffset[offsetBytes] = synthDt
                        resolvedBaseInfo[offsetBytes] = ResolvedBase(synthName, gap)
                        val reason = if (dt == null || dt.isZeroLength || dt.length <= 0) {
                            "Ref unresolved, synthesised $gap-byte placeholder"
                        } else {
                            "${dt.name} (${dt.length}b) larger than gap ($gap b); synthesised $gap-byte placeholder"
                        }
                        diagnostics.recordDegradation(
                            "base-synthesized",
                            "${ast.nameOrId}@+$offsetBytes",
                            reason,
                        )
                    }

                    // Synthesised placeholders stay as Ghidra's default Undefined1 — skip insertion.
                    val ops = body.bases
                        .sortedBy { it.offsetBits }
                        .mapNotNull { base ->
                            val off = (base.offsetBits / 8).toInt()
                            val info = resolvedBaseInfo[off] ?: return@mapNotNull null
                            if (info.simpleName.startsWith("unknown_")) return@mapNotNull null
                            val prefix = if (base.isVirtual) "_vbase_" else "_base_"
                            InsertOp(
                                offsetBytes = off,
                                fieldName = prefix + info.simpleName,
                                comment = buildString {
                                    append(base.access.name.lowercase())
                                    if (base.isVirtual) append(" virtual")
                                    append(" base")
                                },
                                baseSimpleName = info.simpleName,
                            )
                        }
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

                val polyBase = ClassBuilderHelpers(resolver).firstPolymorphicBase(body)
                // Any vptr at a base-occupied offset is inherited — base owns it. Skip it.
                val baseOffsets = body.bases.map { it.offsetBits }.toSet()

                for (field in body.fields) {
                    if (field.isStatic) continue

                    val isParserEmittedVptr =
                        field.name.startsWith("_vptr$") || field.name.startsWith("_vptr.") || field.name == "_vptr"
                    if (
                        isParserEmittedVptr &&
                        (
                            (polyBase != null && field.offsetBits == polyBase.offsetBits) ||
                                field.offsetBits in baseOffsets
                            )
                    ) {
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
                    // Prefer stab-declared size for zero-length placeholders so the slot stays the right width.
                    val stabBytes = (field.sizeBits / 8).toInt()
                    val len = when {
                        ft.length <= 0 -> stabBytes.takeIf { it > 0 } ?: 4
                        ft.isZeroLength && stabBytes > 0 -> {
                            // Tracked placeholders get widened in place by materialiseAll — don't degrade.
                            if (ft !in placeholders.values) {
                                diagnostics.recordDegradation(
                                    "field-stub-padded",
                                    "${ast.ghidraName}.${field.name}",
                                    "type=${ft.name} (zero-length); padding to stab-declared $stabBytes bytes",
                                )
                            }
                            stabBytes
                        }
                        else -> ft.length
                    }
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

                // Surface ≥4-byte runs of unnamed Undefined1 — auto-fill makes "gap between components"
                // useless, but a long run says the stab didn't tell us about that range.
                if (struct is Structure) {
                    val componentRecords = struct.components.map { c ->
                        Triple(c.fieldName, Pair(c.offset, c.length), c.dataType.name)
                    }
                    val holes = detectUndefinedRuns(componentRecords, minRunBytes = 4)
                    val qualifiedName = "$category/${ast.ghidraName}"
                    diagnostics.recordStructGaps(qualifiedName, holes)
                    if (holes.isNotEmpty()) {
                        val bytesInHoles = holes.sumOf { (it.lengthBits / 8).toInt() }
                        val totalBytes = struct.length
                        if (totalBytes > 0 && bytesInHoles * 4 >= totalBytes) {
                            diagnostics.recordDegradation(
                                "struct-mostly-undefined",
                                "$category/${ast.ghidraName}",
                                "$bytesInHoles of $totalBytes bytes are unnamed Undefined1 across ${holes.size} run(s)",
                            )
                        }
                    }
                }

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

            is TypeDecl.FunctionT -> buildFunctionDefinition(
                category = category,
                name = ast.ghidraName,
                ret = body.ret,
                params = body.params,
                thisType = null,
                callingConvention = null,
                at = ast.ghidraName,
            )

            is TypeDecl.Method -> buildFunctionDefinition(
                category = category,
                name = ast.ghidraName,
                ret = body.ret,
                params = body.params,
                thisType = dataTypeFor(body.cls) ?: undef("method-this-cls", ast.ghidraName, body.cls),
                callingConvention = "__thiscall",
                at = ast.ghidraName,
            )

            is TypeDecl.XRef -> {
                // Alias this id to the canonical (kind, tagName) so InlineDef'd XRefs (gcc's typeinfo
                // helpers like `__si_class_type_info_pseudo`) don't materialise as separate empties.
                resolver.lookupByXRef(body)
                    ?.let { canonical -> tryGetExisting(canonical.id)?.also { byId[ast.id] = it } }
                    ?: placeholder.also { xrefStubs.add(it) }
            }

            is TypeDecl.Ref -> tryGetExisting(body.id)
                ?: if (isVoidSelfRef(body.id) || body.id == ast.id) {
                    VoidDataType()
                } else {
                    diagnostics.recordDegradation(
                        "dangling-ref",
                        ast.nameOrId,
                        "ref to ${body.id} from ${ast.source}",
                    )
                    Undefined4DataType.dataType
                }
        }

    /**
     * Find a DataType by simple name across [allCreatedDataTypes]. On multiple matches, prefer
     * the one at [preferredCategory] (e.g. `/std` for `/Demangler/std/string`).
     */
    fun findByName(simpleName: String, preferredCategory: CategoryPath? = null): DataType? {
        val fromExtras = extrasByName[simpleName].orEmpty()
        // Residual: typedefs registered via byId.putIfAbsent skip extrasByName, so scan.
        val fromById = byId.values.filter { it.name == simpleName }
        val matches = (fromExtras + fromById).distinct()
        if (matches.isEmpty()) return null
        if (matches.size == 1) return matches.single()
        if (preferredCategory != null) {
            matches.firstOrNull { it.categoryPath == preferredCategory }?.let { return it }
        }
        log(
            "demangler-ambiguous",
            "Multiple matches for '$simpleName' (preferred=$preferredCategory): " +
                matches.joinToString { "${it.pathName}(${it::class.simpleName})" },
        )
        diagnostics.inc("demangler-ambiguous")
        return null
    }
}

/**
 * Walk a struct's components and report runs of unnamed Undefined1 of length ≥ [minRunBytes].
 * Each input triple is `(fieldName, (offsetBytes, lengthBytes), typeName)`. The returned [GapRecord]s
 * carry the nearest named field on each side as `prevField` / `nextField`.
 */
fun detectUndefinedRuns(
    componentRecords: List<Triple<String?, Pair<Int, Int>, String>>,
    minRunBytes: Int = 4,
): List<GapRecord> {
    val out = mutableListOf<GapRecord>()
    val sorted = componentRecords.sortedBy { it.second.first }

    var runStartIdx = -1
    var runStart = -1
    var runEnd = -1

    fun flushRun(prevName: String?, nextName: String?) {
        if (runStartIdx < 0) return
        val runBytes = runEnd - runStart
        if (runBytes >= minRunBytes) {
            out.add(
                GapRecord(
                    offsetBits = (runStart * 8).toLong(),
                    lengthBits = (runBytes * 8).toLong(),
                    prevField = prevName,
                    nextField = nextName,
                ),
            )
        }
        runStartIdx = -1
    }

    for ((i, comp) in sorted.withIndex()) {
        val (name, offsetLen, typeName) = comp
        val isUnnamed = name.isNullOrEmpty()
        val isUndef = typeName.startsWith("undefined")
        if (isUnnamed && isUndef) {
            if (runStartIdx < 0) {
                runStartIdx = i
                runStart = offsetLen.first
            }
            runEnd = offsetLen.first + offsetLen.second
        } else {
            val prevName = if (runStartIdx > 0) sorted[runStartIdx - 1].first else null
            flushRun(prevName, name)
        }
    }
    val prevName = if (runStartIdx > 0) sorted[runStartIdx - 1].first else null
    flushRun(prevName, null)
    return out
}

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
