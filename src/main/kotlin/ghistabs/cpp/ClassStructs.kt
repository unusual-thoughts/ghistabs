package ghistabs.cpp

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.Structure
import ghidra.program.model.gclass.ClassUtils
import ghistabs.diagnose.DiagnosticSink

/**
 * Describes this struct as [owner]'s [table], led by the offset tag Ghidra 12.1's `ClassUtils.isVTable`
 * matches: the [offset] of the `{vfptr}` that points at it. Without a known, non-negative offset there
 * is no tag, since a wrong one would misplace Ghidra's vxtable replacement.
 */
internal fun Structure.describeVxTable(owner: String, table: String, offset: Long?) {
    val vfptrOffset = offset?.takeIf { it >= 0 }
    val text = "$owner's $table: what its {${ClassUtils.VFPTR}}" +
        vfptrOffset?.let { " at +$it" }.orEmpty() + " points at"
    val tag = vfptrOffset?.let { ClassUtils::class.createVxTableDescriptionOffsetTag(it) }
    description = listOfNotNull(tag, text).joinToString(" ")
}

/** Offset of the first `{vfptr}` in this struct, its own or one inherited through a base subobject. */
internal fun Structure.vfptrOffset(): Int? = definedComponents.firstNotNullOfOrNull { c ->
    when {
        c.fieldName == ClassUtils.VFPTR -> c.offset
        c.isBaseField() -> (c.dataType as? Structure)?.vfptrOffset()?.let { c.offset + it }
        else -> null
    }
}

/** The direct base whose `{vfptr}` the class's own is, when it shares one. */
internal fun Structure.primaryBase(): String? {
    val vfptr = vfptrOffset() ?: return null
    return definedComponents.firstOrNull { c ->
        c.isBaseField() && (c.dataType as? Structure)?.vfptrOffset()?.let { c.offset + it } == vfptr
    }?.dataType?.name
}

/**
 * Offset of the `{vfptr}` inside base subobject [base], where a gcc 2.x secondary vtable's pointer
 * sits. Matches only a whole base: a split primary base has no vptr of its own.
 */
internal fun Structure.vfptrOffsetOfBase(base: String): Int? = definedComponents.firstNotNullOfOrNull { c ->
    val dt = c.dataType as? Structure
    when {
        !c.isBaseField() || dt == null -> null
        dt.name == base.leafName -> dt.vfptrOffset()?.let { c.offset + it }
        else -> dt.vfptrOffsetOfBase(base)?.let { c.offset + it }
    }
}

/** [ClassNaming.isBaseField], off a live component instead of a bare field name. */
fun DataTypeComponent.isBaseField() = ClassNaming.isBaseField(fieldName.orEmpty())

/** Lays [dt] at [offset] in [struct] as a base subobject, and reports how that went. */
internal fun DiagnosticSink.placeBase(
    struct: Structure,
    offset: Int,
    dt: DataType,
    isVirtual: Boolean,
    comment: String,
    fieldName: String,
    qualifiedName: String,
) {
    val (applied, failed) = if (isVirtual) {
        "vbase-applied" to "vbase-layout-failed"
    } else {
        "inheritance-applied" to "base-layout-failed"
    }
    runCatching { struct.replaceAtOffset(offset, dt, dt.length, fieldName, comment) }
        .onSuccess { debug(applied) }
        .onFailure {
            degradation(failed, qualifiedName.member(dt.name), it.message)
            if (!isVirtual) debug("inheritance-failed")
        }
}
