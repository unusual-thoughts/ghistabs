package ghicpp

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
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

/** The class's struct where `RecoverClassesFromRTTIScript` files it. */
fun Program.classStruct(ns: GhidraClass) =
    dataTypeManager.getDataType(ClassNaming.vftableCategory(ns), ns.name) as? Structure

/**
 * Gives [ns] a [classStruct] of [size] bytes, or grows its own to them. Where its last field is one of its own
 * `<Class>_data` structs, that grows with it, so the fields its constructors store past the old end are refilled
 * there. A base's `_fields` part keeps its size: it is the base's, which grew none.
 */
fun Program.sizeClassStruct(ns: GhidraClass, size: Int) {
    if (size <= 0) return
    when (val struct = classStruct(ns)) {
        null -> dataTypeManager.addDataType(
            StructureDataType(ClassNaming.vftableCategory(ns), ns.name, size),
            DataTypeConflictHandler.KEEP_HANDLER,
        )

        else if struct.isZeroLength -> struct.growStructure(size)

        else if struct.length < size -> {
            val last = struct.definedComponents.lastOrNull()?.takeIf { it.endOffset == struct.length - 1 }
            val data = (last?.dataType as? Structure)?.takeIf { it.isDataOf(ns, struct) }
            struct.growStructure(size - struct.length)
            if (last != null && data != null) {
                data.growStructure(size - last.offset - data.length)
                struct.replaceAtOffset(last.offset, data, data.length, last.fieldName, last.comment)
            }
        }
    }
}

/** Whether this is one of [ns]'s own `<Class>_data` structs, filed beside its [struct]. */
private fun Structure.isDataOf(ns: GhidraClass, struct: Structure) =
    categoryPath == struct.categoryPath && name.startsWith(ns.name + ClassNaming.DATA)
