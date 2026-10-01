package ghistabs.materialize

import ghidra.program.model.data.*
import ghidra.program.model.data.Enum as GhidraEnum

/**
 * Thin layer over [dtm]: resolves types into it under one shared conflict handler, and records which
 * of them this import registered. Lookups always go to the DTM itself; [registered] is provenance, not
 * a cache. The DTM can't say "is this ours": analysis, the loader's archives and the demangler file
 * types in the same categories, and a re-import's type replaced or adopted in place keeps its earlier
 * DTM id.
 */
open class DtmRegistry(internal val dtm: DataTypeManager) {
    // Replace-empty, not keep: when we file a type under its namespace category (scope attribution), it
    // collides with the empty this-param shadow Ghidra's demangler forged there (`std::X::method` → empty
    // `/std/X`). KEEP_HANDLER would return that empty shadow and discard our filled type, so every
    // reference resolves to undefined; REPLACE_EMPTY_STRUCTS fills the shadow with ours (and still
    // RENAME_AND_ADDs two genuinely-distinct non-empty types, like DEFAULT_HANDLER).
    private val conflictHandler = DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER

    /** Ids of the types in the DTM before this import: an earlier import's, and analysis's own. */
    private val preexisting = dtm.allDataTypes.asSequence().mapTo(HashSet()) { dtm.getID(it) }

    /**
     * [conflictHandler], except against a type of the same kind that predates this import. That is an
     * earlier import's: a re-import (`Tools > Stabs > Re-import`, or a saved program run again) builds
     * the same types again, and [conflictHandler] would fork a `.conflict` beside each, which every use
     * then points at. A struct, union or enum is reset in place to what this import builds. A function
     * definition is kept as it stands: a swept vftable slot is typed off its target's signature, which
     * that import has since typed, so what this one builds is not what it was.
     *
     * Only the type being resolved gets this: its dependencies go through [conflictHandler].
     */
    private val reimportHandler = object : DataTypeConflictHandler() {
        override fun resolveConflict(added: DataType, existing: DataType): ConflictResult = when {
            dtm.getID(existing) !in preexisting -> conflictHandler.resolveConflict(added, existing)
            added is FunctionDefinition && existing is FunctionDefinition -> ConflictResult.USE_EXISTING
            existing.isSameKindAs(added) -> ConflictResult.REPLACE_EXISTING
            else -> conflictHandler.resolveConflict(added, existing)
        }

        override fun shouldUpdate(source: DataType, local: DataType) = false

        override fun getSubsequentHandler() = conflictHandler
    }

    private fun DataType.isSameKindAs(other: DataType) = when (other) {
        is Structure -> this is Structure
        is Union -> this is Union
        is GhidraEnum -> this is GhidraEnum
        else -> false
    }

    /** Resolve [this] into the DTM under the shared conflict handler; returns the DTM-resident instance
     *  (may differ from [this]). No bookkeeping — for stubs recorded elsewhere, or later. */
    protected fun DataType.resolveIntoDtm(handler: DataTypeConflictHandler = conflictHandler): DataType =
        dtm.resolve(this, handler)

    /** [resolveIntoDtm] over an earlier import's type of the same kind: see [reimportHandler]. */
    protected fun DataType.resolveAgain(): DataType = resolveIntoDtm(reimportHandler)

    /** What this import registered here: typedefs, vftable and base-subobject structs, slot definitions. */
    private val registered = LinkedHashSet<DataType>()

    /** Everything [register]ed or [adopt]ed so far. */
    internal val registeredTypes: Set<DataType> get() = registered

    /** [resolveIntoDtm], recorded in [registered]. Returns the DTM-resolved instance (may differ). */
    internal fun register(dt: DataType, handler: DataTypeConflictHandler = conflictHandler) =
        dt.resolveIntoDtm(handler).also { registered.add(it) }

    /** [register] for a vftable slot's function definition, over an earlier import's: see [reimportHandler]. */
    internal fun registerAgain(dt: DataType): DataType = register(dt, reimportHandler)

    /**
     * Get-or-create a DTM-resident DataType of type [T] at `(category, name)`. One found there is
     * returned as it stands, and one an earlier import left is registered as this one's, with the slot
     * definitions it points at, so a re-import's registry reads as the first's did.
     */
    internal inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T =
        when (val dt = dtm.getDataType(category, name)) {
            is T -> adopt(dt)
            else -> register(build()) as T
        }

    /**
     * [existing] registered as this import's, as it stands, with the function definitions its slots
     * point at in its category or below it (a secondary's sit in an `internal_<i>` one). Kept rather
     * than rebuilt: a swept vftable slot is typed off its target's signature, which the earlier import
     * has since typed, so rebuilding it would not give back what it was.
     */
    internal fun <T : DataType> adopt(existing: T): T = existing.also {
        if (!registered.add(it)) return it
        for (c in (it as? Composite)?.definedComponents.orEmpty()) {
            val fd = (c.dataType as? Pointer)?.dataType as? FunctionDefinition ?: continue
            if (fd.categoryPath.isAncestorOrSelf(it.categoryPath)) adopt(fd)
        }
    }
}
