package ghistabs.materialize.cpp

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.symbol.Namespace
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Names Ghidra's own class-recovery machinery round-trips on. None of it is an ABI's decision:
 * `RecoveredClassHelper` and shift-S look for `<Class>_vftable` under `/ClassDataTypes/<ns>/<Class>/`
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

    /**
     * Where a class's vftables go: `/ClassDataTypes/` and then its namespace path, the class itself
     * last, as `ExtendedFlatProgramAPI.createDataTypeCategoryPath` files them. shift-D
     * (`RecoveredClassHelper.getClassNamespace`) reads the class back by turning that path into
     * `a::b::Class`, so a table filed under its leaf alone is skipped for any scoped class.
     */
    fun vftableCategory(classPath: List<String>): CategoryPath =
        classPath.fold(classDataTypesRoot) { path, seg -> CategoryPath(path, seg) }

    /** [vftableCategory] of the class [ns] is. */
    fun vftableCategory(ns: Namespace) = vftableCategory(ns.getPathList(true).toList())

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
