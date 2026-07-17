package ghistabs.materialize

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.materialize.itanium.RttiStructs
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
    internal val byId = mutableMapOf<GlobalTypeId, DataType>()
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

    /**
     * Resolve [dt] into the DTM and remember it. Returns the DTM-resolved instance (may differ).
     * If there is an id attached to the type, caches the result under [id] for [dataTypeFor].
     * Otherwise save it to extrasByName
     */
    internal fun register(dt: DataType, id: GlobalTypeId? = null): DataType {
        val resolved = dtm.resolve(dt, conflictHandler)
        when (id) {
            null -> extrasByName.getOrPut(resolved.name) { LinkedHashSet() }.add(resolved)
            else -> byId[id] = resolved
        }
        return resolved
    }

    /** Get-or-create a DTM-resident DataType of type [T] at `(category, name)`. */
    internal inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T =
        when (val dt = dtm.getDataType(category, name)) {
            is T -> dt
            else -> register(build()) as T
        }

    internal fun getOrMaterialize(gId: GlobalTypeId) =
        byId[gId] ?: placeholders[gId] ?: harvest.getType(gId)?.let { raw ->
            BuiltinTable.resolve(raw.body)?.also { byId[gId] = it }
                // Struct/Union: empty placeholder so self-recursive Refs cycle-break;
                // mutated in-place when materializeAll reaches this id.
                ?: if (raw.body is TypeDecl.Struct) {
                    makePlaceholder(raw, CategoryPath("/stabs")).also { placeholders[gId] = it }
                } else {
                    // Pointer/Array/Const/etc. — materializable now. Without this,
                    // a calling field-fill path would store an empty placeholder
                    // instead of e.g. `char *` (`_Alloc_hider._M_p` regression).
                    materializeTopLevel(raw)
                }
        }

    /** Materialized DataType for [id], authoritative for `(category, name)`. Prefer over `dtm.getDataType`. */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]
}
