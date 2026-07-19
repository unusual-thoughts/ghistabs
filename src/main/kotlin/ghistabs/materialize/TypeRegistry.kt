package ghistabs.materialize

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.CanonicalGroup
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.materialize.itanium.RttiStructs
import ghistabs.parse.CATEGORY
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * DataType cache and DTM facade: owns the id→DataType map, resolves types into the DTM under a
 * shared conflict handler, and hands back placeholders for cycle-breaking. The TypeDecl/TypeAst
 * interpreters live in [Materialization] ([resolveRef]/[materializeBody]/[materializeAll]),
 * placeholder construction in [Placeholders] ([makePlaceholder]), and degradation reporting in
 * [TypeDiagnostics].
 */
class TypeRegistry(
    internal val dtm: DataTypeManager,
    sink: DiagnosticSink,
    internal val diagnostics: StabsDiagnostics,
    internal val harvest: Harvest,
    internal val resolver: TypeResolver,
    internal val monitor: TaskMonitor = TaskMonitor.DUMMY,
) : DiagnosticSink by sink {
    private val byId = mutableMapOf<GlobalTypeId, DataType>()
    internal val placeholders = mutableMapOf<GlobalTypeId, DataType>()

    // Baseline the DTM's `.conflict` census at construction (before any of our passes touch the DTM;
    // harvest doesn't). Ghidra's own analysis may have forked some, so the end-of-import delta
    // ([reportConflictDelta]) attributes only the forks the stabs import introduced.
    internal val conflictsBefore = dtm.conflictCount()

    /** XRef stubs that fell through to placeholders. Use sites are flagged via [recordXRefStubAt]. */
    internal val xrefStubs = mutableSetOf<DataType>()

    /** Id-less DataType registrations (typedefs, vftable/vtable composites, FunctionDefinitions). */
    private val extrasByName = LinkedHashMap<String, LinkedHashSet<DataType>>()

    /** Every DataType this importer materialized or registered. */
    internal val allCreatedDataTypes by lazy {
        LinkedHashSet<DataType>().apply {
            addAll(byId.values)
            for (bucket in extrasByName.values) addAll(bucket)
        }
    }

    /**
     * Compromised DataTypes by reason — see [computeDegraded]. Lazily computed the first time
     * [reasonFor] (or [compromisedTypes]) is hit; by then [materializeAll] has already populated
     * [byId] and [xrefStubs].
     */
    internal val degradedBy: Map<DataType, String> by lazy { computeDegraded() }

    // Replace-empty, not keep: when we file a type under its namespace category (scope attribution), it
    // collides with the empty this-param shadow Ghidra's demangler forged there (`std::X::method` → empty
    // `/std/X`). KEEP_HANDLER would return that empty shadow and discard our filled type, so every
    // reference resolves to undefined; REPLACE_EMPTY_STRUCTS fills the shadow with ours (and still
    // RENAME_AND_ADDs two genuinely-distinct non-empty types, like DEFAULT_HANDLER).
    private val conflictHandler = DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER

    internal val rttiStructs by lazy { RttiStructs(dtm) }

    // ── The only writers of byId / placeholders / xrefStubs. [cache] sets the authoritative
    // resolution for an id; [cacheIfAbsent] is the alias/member fan-out that must not clobber a
    // winner already in the slot; [seedPlaceholder] builds an empty cycle-break stub that
    // [materializeAll] later fills in place and [sharePlaceholder] points a member id at one;
    // [markXRefStub] tags a placeholder that never resolved, for degradation reporting. Each
    // returns its dt so it composes inside a resolution chain. ([register] layers [resolveIntoDtm] +
    // [cache] for freshly-built types — the DTM-registering counterpart to bare [cache].) ──

    internal fun <T : DataType> cache(id: GlobalTypeId, dt: T): T = dt.also { byId[id] = it }

    internal fun cacheIfAbsent(id: GlobalTypeId, build: () -> DataType): DataType = byId.getOrPut(id, build)
    internal fun cacheIfAbsent(id: GlobalTypeId, dt: DataType?): DataType? = dt?.let { byId.getOrPut(id) { it } }

    /** Get-or-create the empty cycle-break stub for [this] under [category]; [materializeAll] fills it. */
    internal fun TypeAst.seedPlaceholder(category: CategoryPath = CATEGORY, reason: String = "fwd-decl"): DataType =
        placeholders.getOrPut(id) { makePlaceholder(this, category, reason) }

    /** Canonical-group fan-out where every member id  shares its winner's in-flight stub.
     * Winners are always XRef-targets (Struct/Union/Enum), so the stub always goes into the
     * DTM up front — in-place fill then lands on the DTM-resident object — and is shared across
     * the group's member ids so a Ref resolved before the winner materializes pulls in that one.
     */
    internal fun CanonicalGroup.seedPlaceholder() {
        val placeholder = makePlaceholder(ast, key.category, name = key.name).resolveIntoDtm()
        for (m in members) placeholders.putIfAbsent(m, placeholder)
    }

    internal fun CanonicalGroup.materialize() {
        val placeholder = placeholders[ast.id]!!
        val materialized = materializeBody(ast, key.category, placeholder)
        if (materialized === placeholder) cache(ast.id, placeholder) else register(materialized, ast.id)
        for (memberId in members) cacheIfAbsent(memberId, materialized)
    }

    internal fun DataType.markXRefStub(): DataType = apply { xrefStubs.add(this) }

    /** Resolve [this] into the DTM under the shared conflict handler; returns the DTM-resident instance
     *  (may differ from [this]). No id/name bookkeeping — for stubs whose id lands in [byId] later. */
    internal fun DataType.resolveIntoDtm(): DataType = dtm.resolve(this, conflictHandler)

    /**
     * [resolveIntoDtm] + remember. Returns the DTM-resolved instance (may differ). With an [id],
     * caches it under [id] for [dataTypeFor]; id-less, buckets it by name in extrasByName.
     */
    internal fun register(dt: DataType, id: GlobalTypeId? = null): DataType {
        val resolved = dt.resolveIntoDtm()
        when (id) {
            null -> extrasByName.getOrPut(resolved.name) { LinkedHashSet() }.add(resolved)
            else -> cache(id, resolved)
        }
        return resolved
    }

    /** Get-or-create a DTM-resident DataType of type [T] at `(category, name)`. */
    internal inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T =
        when (val dt = dtm.getDataType(category, name)) {
            is T -> dt
            else -> register(build()) as T
        }

    /**
     * Id → DataType, resolved lazily. Returns the cached type or its in-flight cycle-break
     * placeholder if present; otherwise resolves the harvested ast:
     *  - an authoritative [substitute] (primitive / RTTI pseudo) is a *final* type, cached in [byId];
     *  - a Struct/Union gets an empty placeholder so self-recursive Refs cycle-break — [materializeAll]
     *    fills it in place;
     *  - anything else (Pointer/Array/Const/…) is materialized now, so a field-fill path stores e.g.
     *    `char *`, not an empty placeholder (`_Alloc_hider._M_p` regression).
     */
    internal fun getOrMaterialize(id: GlobalTypeId): DataType? =
        byId[id] ?: placeholders[id] ?: harvest.getType(id)?.let { ast ->
            ast.substitute()?.let { cache(id, it) }
                ?: if (ast.body is TypeDecl.Struct) {
                    ast.seedPlaceholder()
                } else {
                    materializeTopLevel(ast)
                }
        }

    /**
     * Authoritative, fully-resolved type for an ast gcc references but never defines: a primitive via
     * [resolveBuiltin], or a `__*_type_info_pseudo` RTTI record via [RttiStructs]. These are final types,
     * not cycle-break stubs — callers cache them in [byId] and must never file them under [xrefStubs].
     */
    internal fun TypeAst.substitute(): DataType? = body.resolveBuiltin()
        ?: rttiStructs.typeInfoLayout(ghidraName)?.also {
            debug("rtti-pseudo-substituted", "name=$ghidraName")
        }

    /** Materialized DataType for [id], authoritative for `(category, name)`. Prefer over `dtm.getDataType`. */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]
}
