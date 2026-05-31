package ghistabs.builder

import ghistabs.parser.BaseDecl
import ghistabs.parser.TypeDecl

/**
 * Resolved base class information: simple name and byte length.
 * Pure data record for InsertOp decision-making.
 */
data class ResolvedBase(val simpleName: String, val lengthBytes: Int)

/**
 * Base field insertion operation for a single C++ base class.
 * Pure data record describing where and how to insert a base subobject.
 */
data class InsertOp(
    val offsetBytes: Int,
    val fieldName: String, // "_base_<Name>" or "_vbase_<Name>"
    val comment: String, // "public base", "protected virtual base", etc.
    val baseSimpleName: String,
)

/**
 * Pure planning core for C++ base class materialization.
 * Decides insertion operations for a derived struct's bases.
 */
object BaseInsertionPlanner {
    /**
     * Plan base class field insertions for a derived struct.
     *
     * @param bases List of base declarations from the struct body.
     * @param resolveBase Callback to resolve a base TypeDecl to name and length.
     *   Returning null skips that base (dangling ref); returning lengthBytes <= 0 skips.
     * @return List of insertion operations, sorted by offset, ready to apply
     *   via Structure.replaceAtOffset(...).
     *
     * Sorting ensures correct application order and predictable output.
     */
    fun planBaseInsertions(
        bases: List<BaseDecl>,
        resolveBase: (TypeDecl) -> ResolvedBase?,
    ): List<InsertOp> = bases.sortedBy { it.offsetBits }.mapNotNull { base ->
        val resolved = resolveBase(base.type) ?: return@mapNotNull null
        if (resolved.lengthBytes <= 0) return@mapNotNull null

        val fieldName = if (base.isVirtual) {
            "_vbase_${resolved.simpleName}"
        } else {
            "_base_${resolved.simpleName}"
        }

        val comment = buildString {
            append(base.access.name.lowercase())
            if (base.isVirtual) append(" virtual")
            append(" base")
        }

        InsertOp(
            offsetBytes = (base.offsetBits / 8).toInt(),
            fieldName = fieldName,
            comment = comment,
            baseSimpleName = resolved.simpleName,
        )
    }
}
