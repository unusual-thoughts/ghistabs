package ghistabs.materialize.cpp

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeComponent
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Names Ghidra's own class-recovery machinery round-trips on. None of it is an ABI's decision:
 * `RecoveredClassHelper` and shift-S look for `<Class>_vftable` under `/ClassDataTypes/<Class>/`
 * whatever compiler produced the record, and `RTTIGccClassRecoverer` spells a non-primary table
 * `internal_vftable`.
 */
object ClassNaming {
    val classDataTypesRoot by lazy { CategoryPath(CategoryPath.ROOT, "ClassDataTypes") }

    // Spelled out rather than taken from ClassUtils.VFTABLE, which only arrives in 12.1.
    const val VFTABLE = "vftable"

    // RTTIGccClassRecoverer#createVfunctionSymbol prefixes "internal_" onto VFTABLE_LABEL for any
    // non-primary vtable; nothing exposes that prefix as a constant, so it is spelled out here.
    const val INTERNAL_VFTABLE = "internal_$VFTABLE"

    // ghistabs' own base-subobject field naming, applied uniformly regardless of the class's ABI.
    const val BASE_PREFIX = "_base_"
    const val VBASE_PREFIX = "_vbase_"

    fun isBaseField(name: String) = name.startsWith(BASE_PREFIX) || name.startsWith(VBASE_PREFIX)

    fun baseFieldName(isVirtual: Boolean, simpleName: String, baseCount: Int) =
        (if (isVirtual) VBASE_PREFIX else BASE_PREFIX) + simpleName.takeIf { baseCount > 1 }.orEmpty()

    fun baseComment(base: TypeDecl.Aggregate.Base<GlobalTypeId>) = buildString {
        append(base.access.name.lowercase())
        if (base.isVirtual) append(" virtual")
        append(" base")
    }
}

/** [ClassNaming.isBaseField], off a live component instead of a bare field name. */
fun DataTypeComponent.isBaseField() = ClassNaming.isBaseField(fieldName.orEmpty())
