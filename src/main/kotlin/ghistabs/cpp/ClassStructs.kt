package ghistabs.cpp

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.Structure
import ghidra.program.model.gclass.ClassUtils
import ghistabs.diagnose.DiagnosticSink

/**
 * Describe [this] as [owner]'s [table], the one the `{vfptr}` at [vfptrOffset] in the class points at.
 * The description leads with the offset tag `ClassUtils.isVTable` (12.1+) recognises a table by, one
 * per table at its own `{vfptr}`'s offset, so a secondary carries the offset of the subobject it
 * serves. No offset, no tag: a guessed one would point Ghidra's vxtable replacement at the wrong word,
 * and a negative one can only come from a misread record.
 */
internal fun Structure.describeVxTable(owner: String, table: String, offset: Long?) {
    val vfptrOffset = offset?.takeIf { it >= 0 }
    val text = "$owner's $table: what its {${ClassUtils.VFPTR}}" +
        vfptrOffset?.let { " at +$it" }.orEmpty() + " points at"
    val tag = vfptrOffset?.let { ClassUtils::class.createVxTableDescriptionOffsetTag(it) }
    description = listOfNotNull(tag, text).joinToString(" ")
}

/**
 * Offset of the first `{vfptr}` in [this], looking through base subobjects in layout order — so it
 * finds the pointer a class inherits through its primary base as well as one it owns, wherever the
 * ABI put it (gcc 2.x appends it after the class's own fields).
 */
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
 * Offset in [this] of the `{vfptr}` inside the base subobject [base] names, looking through base
 * subobjects in layout order — where a gcc 2.x secondary vtable's pointer sits in the class. The base
 * is found by name, whole: a primary base `VfptrModel.SPLIT_BASE` took apart is a `_fields_` run
 * with no vptr left, and its table is the class's own.
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
