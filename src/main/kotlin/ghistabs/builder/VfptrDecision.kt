package ghistabs.builder

/**
 * Snapshot of a component at a target offset, used for vfptr placement decisions.
 */
data class FirstComponentSnapshot(
    val fieldName: String?,
    val offsetBytes: Int,
    val isUndefined: Boolean,
)

/**
 * Action to take on vfptr field placement.
 */
sealed class VfptrAction {
    /** Inherited from a polymorphic base — do not insert. */
    object SkipInheritedFromBase : VfptrAction()

    /** Insert vfptr at the given offset. */
    data class Insert(val offsetBytes: Int) : VfptrAction()

    /** Replace existing field at offset with vfptr. */
    data class Replace(val offsetBytes: Int, val wasFieldName: String) : VfptrAction()

    /** Already canonical — field is correct vfptr type/name. */
    object AlreadyCanonical : VfptrAction()

    /** Collision with non-vptr field at offset — cannot place vfptr. */
    data class CollisionAt(val offsetBytes: Int, val occupantFieldName: String) : VfptrAction()
}

/**
 * Pure decision logic for vfptr field placement.
 * Extracted from ClassBuilder.ensureVfptrFirstField for unit testing.
 */
object VfptrDecision {
    /**
     * Choose action to apply to vfptr field placement.
     *
     * @param hasPolymorphicBaseSubobject true if this class inherits from a polymorphic base
     * @param parserVptrOffsetBytes offset (in bytes) of parser-emitted _vptr field, or null if absent
     * @param componentAtTargetOffset snapshot of any component already at the target offset, or null
     * @param canonicalVfptrFieldName expected name for the vfptr field (e.g. "{vfptr}")
     * @return action to perform
     */
    fun chooseVfptrAction(
        hasPolymorphicBaseSubobject: Boolean,
        parserVptrOffsetBytes: Int?,
        componentAtTargetOffset: FirstComponentSnapshot?,
        canonicalVfptrFieldName: String,
    ): VfptrAction {
        // If inheriting from a polymorphic base, vfptr comes from the base.
        if (hasPolymorphicBaseSubobject) return VfptrAction.SkipInheritedFromBase

        val targetOffset = parserVptrOffsetBytes ?: 0

        // If target slot already has the canonical vfptr, we are done.
        if (
            componentAtTargetOffset != null &&
            componentAtTargetOffset.offsetBytes == targetOffset &&
            componentAtTargetOffset.fieldName == canonicalVfptrFieldName
        ) {
            return VfptrAction.AlreadyCanonical
        }

        // If slot is empty or undefined, insert vfptr.
        if (componentAtTargetOffset == null || componentAtTargetOffset.isUndefined) {
            return VfptrAction.Insert(targetOffset)
        }

        // If slot is occupied by a parser-emitted vptr variant, replace it.
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
