package ghistabs.cpp

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypePath
import ghidra.program.model.symbol.Namespace
import ghistabs.at

/**
 * The names Ghidra's class recovery looks for, the same for every ABI: `<Class>_vftable` under
 * `/ClassDataTypes/<ns>/<Class>/`, and the `internal_vftable`, `construction-vftable` and
 * `vftable_for_<Base>` labels `RTTIGccClassRecoverer` gives.
 */
object ClassNaming {
    val classDataTypesRoot by lazy { CategoryPath(CategoryPath.ROOT, "ClassDataTypes") }

    // Spelled out rather than taken from ClassUtils.VFTABLE, which only arrives in 12.1.
    const val VFTABLE = "vftable"

    // What GnuDemangler names a `_ZTV…` symbol (no f) and a `_ZTI…` one, in the class's namespace: both
    // take GnuDemanglerParser's AddressTableHandler, whose name is the prefix before " for ".
    const val VTABLE = "vtable"
    const val TYPEINFO = "typeinfo"

    // RTTIGccClassRecoverer#createVfunctionSymbol prefixes "internal_" onto VFTABLE_LABEL for any
    // non-primary vtable; nothing exposes that prefix as a constant, so it is spelled out here.
    const val INTERNAL_PREFIX = "internal_"

    // RTTIGccClassRecoverer#createVtableSymbol/createVfunctionSymbol, after INTERNAL_PREFIX.
    const val CONSTRUCTION_PREFIX = "construction-"

    // RTTIGccClassRecoverer#updateMultiVftableLabels and RecoveredClassHelper#createEmptyVfTableStructs.
    const val FOR_INFIX = "_for_"

    // ghistabs' own base-subobject field naming, applied uniformly regardless of the class's ABI.
    const val BASE_PREFIX = "_base_"
    const val VBASE_PREFIX = "_vbase_"

    // A split base's own fields, embedded in it as the `<Base>_fields_<from>_<until>` its deriving classes hold.
    const val FIELDS = "_fields"

    fun vtableLabel(internal: Boolean, construction: Boolean = false) = prefix(internal, construction) + VTABLE

    /** A vftable's label: `vftable_for_<base>` given a [base], else `vftable` with its prefixes. */
    fun vftableLabel(internal: Boolean, construction: Boolean = false, base: String? = null) = when {
        base != null && !construction -> vftableForLabel(base)
        else -> prefix(internal, construction) + VFTABLE
    }

    private fun prefix(internal: Boolean, construction: Boolean) =
        INTERNAL_PREFIX.takeIf { internal }.orEmpty() + CONSTRUCTION_PREFIX.takeIf { construction }.orEmpty()

    /** The label of a class's table serving [base], once the class has more than one: `vftable_for_<base>`. */
    fun vftableForLabel(base: String) = "$VFTABLE$FOR_INFIX$base"

    /** Whether [name] labels one of a class's own vftables: `vftable`, `internal_vftable`, `vftable_for_<Base>`. */
    fun isClassVftableLabel(name: String) =
        name == VFTABLE || name == vftableLabel(internal = true) || name.startsWith(vftableForLabel(""))

    /** Whether [name] labels any vftable, a construction one's included. */
    fun isVftableLabel(name: String) =
        isClassVftableLabel(name) || name == vftableLabel(false, true) || name == vftableLabel(true, true)

    fun isBaseField(name: String) = name.startsWith(BASE_PREFIX) || name.startsWith(VBASE_PREFIX)

    /**
     * `/ClassDataTypes/` plus the class's full namespace path, where Ghidra files vftables. shift-D reads
     * the class back from this path, so it must be the whole scope, not just the leaf.
     */
    fun vftableCategory(classPath: List<String>): CategoryPath =
        classPath.fold(classDataTypesRoot) { path, seg -> CategoryPath(path, seg) }

    /** [vftableCategory] of the class [ns] is. */
    fun vftableCategory(ns: Namespace) = vftableCategory(ns.getPathList(true).toList())

    fun vftableName(className: String) = "${className}_$VFTABLE"

    /** `<leaf>_vftable` in the class [ns]'s category; [leaf] may spell the class otherwise than [ns] does. */
    fun vftablePath(ns: Namespace, leaf: String = ns.name) = vftableCategory(ns).at(vftableName(leaf))
    fun vftablePath(classPath: List<String>) = DataTypePath(vftableCategory(classPath), vftableName(classPath.last()))

    /**
     * The name of table [index] of [count] (0 the primary, then secondaries by address): `<leaf>_vftable`
     * when alone, else `<leaf>_vftable_for_<base>`, or `<leaf>_vftable<index>` without a [base].
     */
    fun vftableName(primary: DataTypePath, index: Int, count: Int, base: String?): String = when {
        count < 2 -> primary.dataTypeName
        base != null -> "${primary.dataTypeName}$FOR_INFIX$base"
        else -> "${primary.dataTypeName}$index"
    }

    /** Where that secondary's slot definitions go, apart from the primary's: `internal_<i>`. */
    fun internalSlotCategory(primary: DataTypePath, i: Int) = CategoryPath(primary.categoryPath, "$INTERNAL_PREFIX$i")

    fun baseFieldName(isVirtual: Boolean, simpleName: String, baseCount: Int) =
        (if (isVirtual) VBASE_PREFIX else BASE_PREFIX) + simpleName.takeIf { baseCount > 1 }.orEmpty()
}
