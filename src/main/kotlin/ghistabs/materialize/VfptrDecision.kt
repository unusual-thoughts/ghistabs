package ghistabs.materialize

/** Component snapshot at a target offset, fed into vfptr placement decisions. */
data class FirstComponentSnapshot(val fieldName: String?, val offsetBytes: Int, val isUndefined: Boolean)

sealed class VfptrAction {
    object SkipInheritedFromBase : VfptrAction()
    data class Insert(val offsetBytes: Int) : VfptrAction()
    data class Replace(val offsetBytes: Int, val wasFieldName: String) : VfptrAction()
    object AlreadyCanonical : VfptrAction()
    data class CollisionAt(val offsetBytes: Int, val occupantFieldName: String) : VfptrAction()
}

/** Pure decision logic for vfptr placement — extracted from `ClassBuilder.ensureVfptrFirstField`. */
object VfptrDecision {
    fun chooseVfptrAction(
        hasPolymorphicBaseSubobject: Boolean,
        parserVptrOffsetBytes: Int?,
        componentAtTargetOffset: FirstComponentSnapshot?,
        canonicalVfptrFieldName: String,
    ): VfptrAction {
        if (hasPolymorphicBaseSubobject) return VfptrAction.SkipInheritedFromBase

        val targetOffset = parserVptrOffsetBytes ?: 0

        if (
            componentAtTargetOffset != null &&
            componentAtTargetOffset.offsetBytes == targetOffset &&
            componentAtTargetOffset.fieldName == canonicalVfptrFieldName
        ) {
            return VfptrAction.AlreadyCanonical
        }

        if (componentAtTargetOffset == null || componentAtTargetOffset.isUndefined) {
            return VfptrAction.Insert(targetOffset)
        }

        // Catches the unresolved/synthesised-base case where polymorphism couldn't be proven
        // but the stab layout still puts a base at the vptr offset — base owns the vfptr.
        val isBaseSubobject = componentAtTargetOffset.fieldName?.let {
            it.startsWith("_base_") || it.startsWith("_vbase_")
        } ?: false
        if (isBaseSubobject) return VfptrAction.SkipInheritedFromBase

        val isParserEmitted = componentAtTargetOffset.fieldName?.let {
            it.startsWith("_vptr$") || it.startsWith("_vptr.") || it == "_vptr"
        } ?: false

        return if (isParserEmitted) {
            VfptrAction.Replace(targetOffset, componentAtTargetOffset.fieldName)
        } else {
            VfptrAction.CollisionAt(targetOffset, componentAtTargetOffset.fieldName ?: "<anon>")
        }
    }
}
