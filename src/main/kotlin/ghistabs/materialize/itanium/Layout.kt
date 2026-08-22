package ghistabs.materialize.itanium

import ghistabs.harvest.HarvestIndex
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Struct.Base
import ghistabs.parse.VirtKind

/** Component snapshot at a target offset, fed into vfptr placement decisions. */
data class FirstComponentSnapshot(val fieldName: String?, val offsetBytes: Int, val isUndefined: Boolean)

sealed class VfptrAction {
    object SkipInheritedFromBase : VfptrAction()
    data class Insert(val offsetBytes: Int) : VfptrAction()
    data class Replace(val offsetBytes: Int, val wasFieldName: String) : VfptrAction()
    object AlreadyCanonical : VfptrAction()
    data class CollisionAt(val offsetBytes: Int, val occupantFieldName: String) : VfptrAction()
}

/** Pure C++ record-layout decisions: where the vfptr goes and how base subobjects are spliced in. */
object Layout {
    /** Extracted from `ClassBuilder.ensureVfptrFirstField` for pure unit testing. */
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

        // Catches the unresolved/synthesized-base case where polymorphism couldn't be proven
        // but the stab layout still puts a base at the vptr offset — base owns the vfptr.
        if (componentAtTargetOffset.fieldName?.let(Itanium::isBaseField) == true) {
            return VfptrAction.SkipInheritedFromBase
        }

        return if (componentAtTargetOffset.fieldName?.let(Itanium::isVptrField) == true) {
            VfptrAction.Replace(targetOffset, componentAtTargetOffset.fieldName)
        } else {
            VfptrAction.CollisionAt(targetOffset, componentAtTargetOffset.fieldName ?: "<anon>")
        }
    }

    fun baseFieldName(isVirtual: Boolean, simpleName: String, baseCount: Int) =
        (if (isVirtual) Itanium.VBASE_PREFIX else Itanium.BASE_PREFIX) + simpleName.takeIf { baseCount > 1 }.orEmpty()

    fun baseComment(base: Base<GlobalTypeId>) = buildString {
        append(base.access.name.lowercase())
        if (base.isVirtual) append(" virtual")
        append(" base")
    }
}

/** Does [typeDecl] inherit a vfptr from a polymorphic base subobject (vs. introducing its own)? */
fun HarvestIndex.hasPolymorphicBaseSubobject(typeDecl: TypeDecl.Struct<GlobalTypeId>) =
    firstPolymorphicBase(typeDecl) != null

/** Lowest-offset polymorphic base, or null. Determines whether to insert a vfptr or inherit. */
fun HarvestIndex.firstPolymorphicBase(typeDecl: TypeDecl.Struct<GlobalTypeId>): Base<GlobalTypeId>? = typeDecl.bases
    .sortedBy { it.offsetBits }
    .firstOrNull { base ->
        resolveBaseAstStatic(base.type)?.run {
            hasVTablePointerMarker ||
                methods.any { it.virt == VirtKind.VIRTUAL } ||
                firstPolymorphicBase(this) != null
        } ?: false
    }

fun HarvestIndex.resolveBaseAstStatic(typeDecl: TypeDecl<GlobalTypeId>): TypeDecl.Struct<GlobalTypeId>? =
    when (typeDecl) {
        is TypeDecl.Ref -> getStruct(typeDecl.id)

        is TypeDecl.XRef -> byXRef(typeDecl)?.body as? TypeDecl.Struct<GlobalTypeId>

        // Prefer the ast at this id (real struct body) over the inline body, which is
        // often a forward XRef. Without the fallback, polymorphism detection misses
        // inherited vfptrs (e.g. DCInst → InlineDef(ExprInst id, XRef body)).
        is TypeDecl.InlineDef -> getStruct(typeDecl.id)
            ?: (typeDecl.inner as? TypeDecl.Struct)
            ?: resolveBaseAstStatic(typeDecl.inner)

        else -> null
    }
