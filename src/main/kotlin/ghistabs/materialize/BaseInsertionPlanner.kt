package ghistabs.materialize

import ghistabs.parse.BaseDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

data class ResolvedBase(val simpleName: String, val lengthBytes: Int)

/** One `_base_<Name>` or `_vbase_<Name>` subobject to splice into a derived struct. */
data class InsertOp(val offsetBytes: Int, val fieldName: String, val comment: String, val baseSimpleName: String)

/** Pure planner for C++ base-class subobject insertion, sorted by offset for stable apply order. */
object BaseInsertionPlanner {
    /** Plan base insertions. [resolveBase] returns null (dangling) or zero-length to skip a base. */
    fun planBaseInsertions(
        bases: List<BaseDecl<GlobalTypeId>>,
        resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase?,
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
