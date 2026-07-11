package ghistabs.materialize.itanium

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.LongLongDataType
import ghidra.program.model.listing.Program
import ghistabs.demangle
import ghistabs.parse.splitQualified

/**
 * Single source of Itanium C++ ABI facts for the gcc/Cygwin corpus: mangled names,
 * conventional field names, category layout, and vtable geometry. Every ABI-specific site
 * references the constants here rather than re-spelling literals.
 */
object Itanium {
    // Itanium mangling prefixes (ABI §5.1.4). Cygwin's PE loader prepends '_' → "__ZT*".
    const val VTABLE_PREFIX = "_ZTV"
    const val TYPEINFO_PREFIX = "_ZTI"
    const val TYPEINFO_NAME_PREFIX = "_ZTS"

    // Demangled name of a `_ZTV…` symbol (GnuDemangler emits "vtable", no f).
    const val DEMANGLED_VTABLE = "vtable"

    // gcc __cxxabiv1 typeinfo classes — owners of the RTTI structs (see RttiStructs).
    const val ABI_NAMESPACE = "__cxxabiv1"
    const val CLASS_TYPE_INFO = "__class_type_info"
    const val SI_CLASS_TYPE_INFO = "__si_class_type_info"
    const val VMI_CLASS_TYPE_INFO = "__vmi_class_type_info"
    const val BASE_CLASS_TYPE_INFO = "__base_class_type_info"

    // Conventional field/label names RecoveredClassHelper / shift-S round-trip on.
    const val VFTABLE = "vftable"
    const val OFFSET_TO_TOP = "offset_to_top"
    const val RTTI = "rtti"
    const val BASE_PREFIX = "_base_"
    const val VBASE_PREFIX = "_vbase_"

    val classDataTypesRoot by lazy { CategoryPath(CategoryPath.ROOT, "ClassDataTypes") }

    /** Vtable header before the function-pointer array: offset_to_top + rtti = 2 pointers. */
    fun vtablePrefixBytes(ptrSize: Int) = 2 * ptrSize

    /** Type of the `offset_to_top` header word (a signed pointer-sized integer). */
    fun offsetToTopType(ptrSize: Int): DataType =
        if (ptrSize == 8) LongLongDataType.dataType else IntegerDataType.dataType

    fun zti(className: String) = "$TYPEINFO_PREFIX${mangleClassName(className)}"
    fun isTemplated(name: String) = '<' in name

    /** gcc emits the vfptr either as the `~%<id>;` stab marker or as a plain `_vptr.<Class>` field. */
    fun isVptrField(name: String) = name.startsWith("_vptr$") || name.startsWith("_vptr.") || name == "_vptr"
    fun isBaseField(name: String) = name.startsWith(BASE_PREFIX) || name.startsWith(VBASE_PREFIX)

    /** Itanium-mangle a nested class name: `Foo`→`3Foo`, `Foo::Bar`→`N3Foo3BarE`. Templates unchanged. */
    fun mangleClassName(name: String): String {
        if (isTemplated(name)) return name
        val parts = splitQualified(name)
        return if (parts.size == 1) {
            "${parts[0].length}${parts[0]}"
        } else {
            "N" + parts.joinToString("") { "${it.length}$it" } + "E"
        }
    }

    /** Closed-form `_ZTV` candidates for [className]. Templates have no closed form — use [decodesToClass]. */
    fun ztvCandidates(className: String): List<String> {
        val mangled = mangleClassName(className)
        return listOf(
            "$VTABLE_PREFIX$mangled", // Itanium canonical
            "_$VTABLE_PREFIX$mangled", // Cygwin/PE leading-underscore variant
            $$"_vt$$${className}$", // gcc2 fallback
            "$className::$DEMANGLED_VTABLE", // some compilers emit this
        )
    }

    /** True if [symbolName] demangles to a vtable for [className]. Handles templated `_ZTV…` names. */
    fun decodesToClass(program: Program, symbolName: String, className: String): Boolean {
        if (!looksLikeZtv(symbolName)) return false
        val obj = program.demangle(symbolName) ?: return false
        return demangledMatchesClass(obj, className)
    }

    /** String-level pre-filter so we don't pay the demangler cost on every label. */
    internal fun looksLikeZtv(symbolName: String) = symbolName.trimStart('_').startsWith("ZTV")

    /** Pure inspection of a demangled object — extracted for unit testing without a real `Program`. */
    internal fun demangledMatchesClass(obj: DemangledObject, className: String): Boolean {
        if (obj !is DemangledAddressTable || obj.name != DEMANGLED_VTABLE) return false
        val chain = generateSequence(obj.namespace) { it.namespace }
            .map { it.name }
            .toList()
            .asReversed()
            .joinToString("::")
        return chain == className
    }
}
