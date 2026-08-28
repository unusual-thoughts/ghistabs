package ghistabs.materialize.itanium

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.LongLongDataType
import ghistabs.Demangler
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

    // Demangled name of a `_ZTV…` symbol (GnuDemangler emits "vtable", no f) and of a `_ZTI…` one.
    // Both take GnuDemanglerParser's AddressTableHandler, whose name is the prefix before " for ".
    const val DEMANGLED_VTABLE = "vtable"
    const val DEMANGLED_TYPEINFO = "typeinfo"

    // gcc __cxxabiv1 typeinfo classes — owners of the RTTI structs (see RttiStructs).
    const val ABI_NAMESPACE = "__cxxabiv1"
    const val TYPE_INFO = "type_info" // std::type_info — root of the __cxxabiv1 hierarchy
    const val CLASS_TYPE_INFO = "__class_type_info"
    const val SI_CLASS_TYPE_INFO = "__si_class_type_info"
    const val VMI_CLASS_TYPE_INFO = "__vmi_class_type_info"
    const val BASE_CLASS_TYPE_INFO = "__base_class_type_info"

    // gcc's internal per-typeinfo "pseudo" struct types (rtti.c create_pseudo_type_info): a
    // typeinfo-vtable ptr + the __*_type_info members. Emitted alongside each _ZTI global but
    // never given a debug definition, so they arrive as unresolved XRefs. VMI appends the base
    // count (`__vmi_class_type_info_pseudo2`) since its __base_info[] length varies.
    const val CLASS_TYPE_INFO_PSEUDO = "__class_type_info_pseudo"
    const val SI_CLASS_TYPE_INFO_PSEUDO = "__si_class_type_info_pseudo"
    const val VMI_CLASS_TYPE_INFO_PSEUDO = "__vmi_class_type_info_pseudo"

    // Conventional field/label names RecoveredClassHelper / shift-S round-trip on.
    const val VFTABLE = "vftable"

    // RTTIGccClassRecoverer's spelling for a non-primary vftable.
    const val INTERNAL_VFTABLE = "internal_vftable"
    const val OFFSET_TO_TOP = "offset_to_top"
    const val RTTI = "rtti"
    const val BASE_PREFIX = "_base_"
    const val VBASE_PREFIX = "_vbase_"

    /**
     * Itanium-mangled `_ZN…` whose first scope is `std::`, `__gnu_cxx::`, or an STL shortcut
     * (`Ss`/`Sa`/`Si`/`So`/`Sd`/`St`). gcc declares these in stabs even when COMDAT-dropped, so a
     * missing Function at the asserted address is expected — routed to `*-inlined-std`.
     */
    private val INLINE_STD_MEMBER = Regex("""^_ZN[KV]*(?:S[adios]|St|9__gnu_cxx)""")

    /**
     * A gcc implicit trivial special member by its Itanium tail: `C[123]`=ctor (in-charge/not-in-charge/
     * allocating), `D[012]`=dtor (deleting/in-charge/not-in-charge), `aS`=operator=; `E` closes the
     * nested-name; the arg list is `v`=(), `RKS_`=(const Self&) or `OS_`=(Self&&).
     */
    private val IMPLICIT_SPECIAL_MEMBER_TAIL = Regex("""(?:C[123]|D[012]|aS)E(?:v|RKS_|OS_)$""")

    // The same `C[123]`/`D[012]` tails, without the implicit-member restriction on the arg list.
    private val CTOR_TAIL = Regex("""C[123]E[a-zA-Z_0-9$]*$""")
    private val DTOR_TAIL = Regex("""D[012]E[a-zA-Z_0-9$]*$""")

    val classDataTypesRoot by lazy { CategoryPath(CategoryPath.ROOT, "ClassDataTypes") }

    /** Vtable header before the function-pointer array: offset_to_top + rtti = 2 pointers. */
    fun vtablePrefixBytes(ptrSize: Int) = 2L * ptrSize.toLong()

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

    /** Closed-form `_ZTV` candidates for [className]. Templates have no closed form — use [vtableClassOf]. */
    fun ztvCandidates(className: String): List<String> {
        val mangled = mangleClassName(className)
        return listOf(
            "$VTABLE_PREFIX$mangled", // Itanium canonical
            "_$VTABLE_PREFIX$mangled", // Cygwin/PE leading-underscore variant
            $$"_vt$$${className}$", // gcc2 fallback
            "$className::$DEMANGLED_VTABLE", // some compilers emit this
        )
    }

    /** The qualified class name a `_ZTV<class>` [symbolName] names (e.g. `std::basic_ios<char,…>`), or
     *  null if it isn't a vtable. Lets a caller demangle the symbol table once into a class→address index
     *  instead of re-scanning + re-demangling every symbol per class
     *  ([ghistabs.materialize.ClassBuilder.resolveVtableAddress]). */
    fun vtableClassOf(symbolName: String): String? {
        if (!looksLikeZtv(symbolName)) return null
        return Demangler.of(symbolName)?.let(::demangledVtableClass)
    }

    /** The qualified class a `_ZTI<class>` typeinfo object belongs to, or null if [symbolName] isn't
     *  one. Unlike its sibling `_ZTS` string, a typeinfo object carries the *class's* own declaration
     *  line, so knowing the class is enough to file it where the class is declared — see §38. */
    fun typeinfoClassOf(symbolName: String): String? {
        if (!looksLikeZti(symbolName)) return null
        return Demangler.of(symbolName)?.let { addressTableClass(it, DEMANGLED_TYPEINFO) }
    }

    private fun String.trimDoubleUnderscore() = if (startsWith("__")) substring(1) else this

    /** An Itanium-mangled name. The Cygwin PE/COFF loader prepends `_`, so they also appear as `__Z…`. */
    fun isProbablyMangled(name: String): Boolean = name.trimDoubleUnderscore().startsWith("_Z")

    /** Data gcc generated for a class rather than anything the source declares — typeinfo objects,
     *  their name strings, vtables. None of it has a source line of its own. */
    fun isGeneratedData(name: String) = name.trimDoubleUnderscore().let { n ->
        listOf(VTABLE_PREFIX, TYPEINFO_PREFIX, TYPEINFO_NAME_PREFIX).any { n.startsWith(it) }
    }

    /** String-level pre-filter so we don't pay the demangler cost on every label. */
    internal fun looksLikeZtv(symbolName: String) = symbolName.trimDoubleUnderscore().startsWith(VTABLE_PREFIX)

    internal fun looksLikeZti(symbolName: String) = symbolName.trimDoubleUnderscore().startsWith(TYPEINFO_PREFIX)

    /** Pure inspection of a demangled object — extracted for unit testing without a real `Program`. */
    internal fun demangledMatchesClass(obj: DemangledObject, className: String) = demangledVtableClass(obj) == className

    /** Qualified class name of a demangled vtable object (`::`-joined namespace chain), or null if [obj]
     *  isn't a vtable address-table. */
    internal fun demangledVtableClass(obj: DemangledObject) = addressTableClass(obj, DEMANGLED_VTABLE)

    /** The class an `<kind> for <class>` address table belongs to, `::`-joined, or null if [obj] is
     *  not one of [kind]. */
    private fun addressTableClass(obj: DemangledObject, kind: String): String? {
        if (obj !is DemangledAddressTable || obj.name != kind) return null
        return generateSequence(obj.namespace) { it.namespace }
            .map { it.name }
            .toList()
            .asReversed()
            .joinToString("::")
    }

    fun isInlineStdMember(name: String): Boolean = INLINE_STD_MEMBER.containsMatchIn(name)

    fun isImplicitTrivialSpecialMember(mangled: String): Boolean =
        mangled.startsWith("_ZN") && IMPLICIT_SPECIAL_MEMBER_TAIL.containsMatchIn(mangled)

    /** In-class display form of a ctor/dtor linkage name — `_ZN3FooC[123]E…` → `Foo`,
     *  `_ZN3FooD[012]E…` → `~Foo`. Itanium emits up to three symbols per ctor/dtor, all carrying one
     *  source-level name; Ghidra tells them apart by address. Null for anything else. */
    fun specialMemberDisplayName(mangled: String, className: String): String? = when {
        CTOR_TAIL.containsMatchIn(mangled) -> className
        DTOR_TAIL.containsMatchIn(mangled) -> "~$className"
        else -> null
    }
}
