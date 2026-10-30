package ghistabs.cpp.abi.itanium

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledFunction
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.LongLongDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import ghistabs.Demangler
import ghistabs.cpp.*
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.Structor
import ghistabs.cpp.abi.StructorRole
import ghistabs.cpp.abi.VtableRecord
import ghistabs.getScalar
import ghistabs.namespaces

/** The Itanium C++ ABI, as gcc >= 3 emits it: its special names, typeinfo classes and vtable header. */
@Suppress("TooManyFunctions")
object Itanium : CxxAbi {
    // Special-name prefixes (ABI §5.1.4). Cygwin's PE loader prepends another `_`: `__ZTV…`.

    /** A class's virtual table. */
    const val VTABLE_PREFIX = "_ZTV"

    /** A VTT, the table of vtables a class with virtual bases hands its bases' constructors and destructors. */
    const val VTABLE_TABLE_PREFIX = "_ZTT"

    /** A construction vtable: a base's vtable as used inside a derived object while that's built. */
    const val CONSTRUCTION_VTABLE_PREFIX = "_ZTC"

    /** A class's `std::type_info` object. */
    const val TYPEINFO_PREFIX = "_ZTI"

    /** The NTBS a typeinfo object's `__type_name` points at. */
    const val TYPEINFO_NAME_PREFIX = "_ZTS"

    /**
     * A class's mangled name, as its typeinfo name spells it: `9TiXmlNode`, `N8CryptoPP3AESE`,
     * `St9exception`, `Sd`. Not a fundamental type (`i`) or a pointer (`P…`). Only the first name is
     * checked closely.
     */
    val CLASS_TYPE_NAME = Regex("""N?(?:S[abdios]|(?:St)?[1-9]\d*[A-Za-z_])\w*""")

    /** Typeinfo names only Itanium spells: a nested name, or one in `std`. gcc 2.x writes `Q2…`, `9type_info`. */
    val ITANIUM_ONLY_NAME = Regex("N.*E|St.*")

    /** A thunk adjusting `this` by a fixed offset. */
    const val NON_VIRTUAL_THUNK_PREFIX = "_ZTh"

    /** A thunk adjusting `this` by an offset read from the vtable (a virtual base's). */
    const val VIRTUAL_THUNK_PREFIX = "_ZTv"

    /** A thunk adjusting both `this` and the returned pointer, for a covariant return. */
    const val COVARIANT_THUNK_PREFIX = "_ZTc"

    private val VTABLE_PREFIXES = listOf(VTABLE_PREFIX, VTABLE_TABLE_PREFIX, CONSTRUCTION_VTABLE_PREFIX)
    private val THUNK_PREFIXES = listOf(NON_VIRTUAL_THUNK_PREFIX, VIRTUAL_THUNK_PREFIX, COVARIANT_THUNK_PREFIX)
    private val TYPEINFO_PREFIXES = listOf(TYPEINFO_PREFIX, TYPEINFO_NAME_PREFIX)

    // Every special name (`_ZT*`: the above) and `_ZG*` (guard variables, reference temporaries).
    private val SPECIAL_PREFIXES = listOf("_ZT", "_ZG")

    // The `__cxxabiv1` typeinfo classes, whose layouts [Rtti] builds.
    const val ABI_NAMESPACE = "__cxxabiv1"
    const val TYPE_INFO = "type_info" // std::type_info — root of the __cxxabiv1 hierarchy
    const val CLASS_TYPE_INFO = "__class_type_info"
    const val SI_CLASS_TYPE_INFO = "__si_class_type_info"
    const val VMI_CLASS_TYPE_INFO = "__vmi_class_type_info"
    const val BASE_CLASS_TYPE_INFO = "__base_class_type_info"

    // The structs gcc types each `_ZTI` with (`rtti.c:create_pseudo_type_info`), which the stabs only
    // reference. VMI's carries its base count: `__vmi_class_type_info_pseudo2`.
    const val CLASS_TYPE_INFO_PSEUDO = "__class_type_info_pseudo"
    const val SI_CLASS_TYPE_INFO_PSEUDO = "__si_class_type_info_pseudo"
    const val VMI_CLASS_TYPE_INFO_PSEUDO = "__vmi_class_type_info_pseudo"

    // The non-class typeinfos' pseudo structs: a pointer's and a member pointer's carry the pointee
    // (`_ZTIPKc`), the rest only the name (`_ZTIc`, an enum's `_ZTI`).
    const val POINTER_TYPE_INFO_PSEUDO = "__pointer_type_info_pseudo"
    const val POINTER_TO_MEMBER_TYPE_INFO_PSEUDO = "__pointer_to_member_type_info_pseudo"
    val NAME_ONLY_TYPE_INFO_PSEUDOS = setOf(
        "__fundamental_type_info_pseudo",
        "__enum_type_info_pseudo",
        "__function_type_info_pseudo",
        "__array_type_info_pseudo",
    )

    const val OFFSET_TO_TOP = "offset_to_top"
    const val RTTI = "rtti"

    /** A member of `std` or `__gnu_cxx`, which the stabs declare even when its COMDAT copy was dropped. */
    private val INLINE_STD_MEMBER = Regex("""^_ZN[KV]*(?:S[adios]|St|9__gnu_cxx)""")

    /** The tail of an implicit constructor, destructor or `operator=`: taking nothing, `const Self&` or `Self&&`. */
    private val IMPLICIT_SPECIAL_MEMBER_TAIL = Regex("""(?:C[123]|D[012]|aS)E(?:v|RKS_|OS_)$""")

    /** A vtable's fixed header: `offset_to_top` and the rtti pointer. */
    fun vtablePrefixBytes(ptrSize: Int) = 2L * ptrSize.toLong()

    /** gcc 3.x spells a member's stab name the way the source does. */
    override val assignmentOperatorName = "operator="

    /** Found by its rtti word ([itaniumVtableRecord]), which says how long its header is. */
    override fun recordAt(program: Program, at: Address) = program.itaniumVtableRecord(at)

    // `size_t` is `unsigned int` (j) on 32-bit targets and `unsigned long` (m) on 64-bit ones.
    override val mangledOperatorNew get() = setOf("_Znwj", "_Znwm")
    override val mangledOperatorDelete get() = setOf("_ZdlPv", "_ZdlPvj", "_ZdlPvm")

    override fun looksLikeVtable(symbolName: String) = symbolName.trimDoubleUnderscore().startsWith(VTABLE_PREFIX)

    /** Templates have no closed form; [ghistabs.cpp.abi.primaryVtableOf] finds those. */
    override fun vtableCandidates(className: String) = mangleClassName(className).let {
        listOf(
            "$VTABLE_PREFIX$it",
            "_$VTABLE_PREFIX$it", // Cygwin's
            className.member(ClassNaming.VTABLE),
        )
    }

    override fun demangledVtableClass(obj: DemangledObject) = addressTableClass(obj, ClassNaming.VTABLE)

    /** `offset_to_top`'s type: a signed pointer-wide integer. */
    fun offsetToTopType(ptrSize: Int): DataType =
        if (ptrSize == 8) LongLongDataType.dataType else IntegerDataType.dataType

    override fun vfptrOffsetOf(record: VtableRecord, program: Program): Long? =
        record.readHeader(program)?.getScalar(OFFSET_TO_TOP)?.signedValue?.let { -it }

    fun zti(className: String) = "$TYPEINFO_PREFIX${mangleClassName(className)}"

    /** A class name as Itanium mangles it: `3Foo`, `N3Foo3BarE`. A template's is returned as is. */
    fun mangleClassName(name: String): String {
        if (name.isTemplated) return name
        val parts = name.nameSegments
        return when (parts.size) {
            1 -> "${parts[0].length}${parts[0]}"
            else -> "N" + parts.joinToString("") { "${it.length}$it" } + "E"
        }
    }

    /** The qualified class a `_ZTI` symbol is the typeinfo of, or null. */
    fun typeinfoClassOf(symbolName: String): String? {
        if (!looksLikeZti(symbolName)) return null
        return Demangler.of(symbolName)?.let { addressTableClass(it, ClassNaming.TYPEINFO) }
    }

    /** `_Z…`, or Cygwin's `__Z…`. */
    override fun isProbablyMangled(name: String): Boolean = name.trimDoubleUnderscore().startsWith("_Z")

    /** Off the class's typeinfo object, labelled `typeinfo` in its namespace. */
    override fun basesOf(program: Program, cls: Namespace): List<BaseDecl>? {
        val zti = program.symbolTable.getSymbols(cls).firstOrNull { it.name == ClassNaming.TYPEINFO } ?: return null
        return Rtti.Reader(program).basesOf(zti.address)
    }

    /** A vtable, typeinfo object or typeinfo name: data gcc generated, with no source line of its own. */
    fun isGeneratedData(name: String) = name.trimDoubleUnderscore().let { n ->
        listOf(VTABLE_PREFIX, TYPEINFO_PREFIX, TYPEINFO_NAME_PREFIX).any { n.startsWith(it) }
    }

    /** A `_ZTI` symbol, told without demangling. */
    internal fun looksLikeZti(symbolName: String) = symbolName.trimDoubleUnderscore().startsWith(TYPEINFO_PREFIX)

    /** The kind of special name [symbolName] is, or null for a source-level or unmangled one. */
    fun specialName(symbolName: String): SpecialName? {
        val name = symbolName.trimDoubleUnderscore()
        fun any(prefixes: List<String>) = prefixes.any(name::startsWith)
        return when {
            any(VTABLE_PREFIXES) -> SpecialName.VTABLE
            any(THUNK_PREFIXES) -> SpecialName.THUNK
            any(TYPEINFO_PREFIXES) -> SpecialName.TYPEINFO
            any(SPECIAL_PREFIXES) -> SpecialName.OTHER
            else -> null
        }
    }

    /** Whether [obj] is [className]'s demangled vtable. */
    internal fun demangledMatchesClass(obj: DemangledObject, className: String) = demangledVtableClass(obj) == className

    /** The qualified class of a demangled `<kind> for <class>` table, or null if [obj] is no [kind]. */
    private fun addressTableClass(obj: DemangledObject, kind: String): String? {
        if (obj !is DemangledAddressTable || obj.name != kind) return null
        return obj.namespaces.qualifiedName
    }

    override fun isInlineStdMember(name: String): Boolean = INLINE_STD_MEMBER.containsMatchIn(name)

    override fun physnameIsImplicit(physname: String): Boolean =
        physname.startsWith("_ZN") && IMPLICIT_SPECIAL_MEMBER_TAIL.containsMatchIn(physname)

    override fun structorOf(mangled: String, className: String?) = ItaniumStructor.of(mangled)

    /** Only the deleting destructor: a vptr store doesn't tell a complete object's structor from a base one's. */
    override fun structorFor(role: StructorRole, func: Function) =
        ItaniumStructor.DELETING_DTOR.takeIf { role == StructorRole.DELETING_DESTRUCTOR }
}

/** Whether [symbolName] starts a group of vtable records: a `_ZTV`, `_ZTC` or `_ZTT`. */
internal fun startsVtableGroup(symbolName: String) = symbolName.trimDoubleUnderscore().let { n ->
    listOf(Itanium.VTABLE_PREFIX, Itanium.CONSTRUCTION_VTABLE_PREFIX, Itanium.VTABLE_TABLE_PREFIX).any(n::startsWith)
}

/** Whether [symbolName] is a construction vtable, `_ZTC`. */
internal fun looksLikeZtc(symbolName: String) =
    symbolName.trimDoubleUnderscore().startsWith(Itanium.CONSTRUCTION_VTABLE_PREFIX)

/** Whether [symbolName] is a VTT, `_ZTT`. */
internal fun looksLikeZtt(symbolName: String) =
    symbolName.trimDoubleUnderscore().startsWith(Itanium.VTABLE_TABLE_PREFIX)

/** The mangled type a `_ZTI` symbol is the typeinfo of (`N8CryptoPP9PublicKeyE`), or null. */
internal fun typeinfoTypeOf(symbolName: String) = symbolName.trimDoubleUnderscore()
    .takeIf { it.startsWith(Itanium.TYPEINFO_PREFIX) }?.removePrefix(Itanium.TYPEINFO_PREFIX)

private fun String.trimDoubleUnderscore() = if (startsWith("__")) substring(1) else this

/** An Itanium constructor or destructor variant, by its code (`C1`, `D0`). gcc emits one function per variant used. */
enum class ItaniumStructor(val code: String, val label: String, override val isDestructor: Boolean) : Structor {
    COMPLETE_CTOR("C1", "complete", false),
    BASE_CTOR("C2", "base", false),

    /** In the ABI; gcc never emits it. */
    ALLOCATING_CTOR("C3", "allocating", false),

    /** gcc's "unified" one, which the complete and base ones call. */
    UNIFIED_CTOR("C4", "unified", false),

    /** gcc >= 7's constructor inherited from a base (`using Base::Base`). */
    COMPLETE_INHERITING_CTOR("CI1", "complete inheriting", false),
    BASE_INHERITING_CTOR("CI2", "base inheriting", false),
    DELETING_DTOR("D0", "deleting", true),
    COMPLETE_DTOR("D1", "complete", true),
    BASE_DTOR("D2", "base", true),
    UNIFIED_DTOR("D4", "unified", true),
    ;

    override val isDeleting get() = this == DELETING_DTOR

    /** The source's name, which every variant shares. */
    override fun displayName(className: String) = if (isDestructor) "~$className" else className

    companion object {
        private val byCode = entries.associateBy { it.code }

        /** A structor code, as `mangle.cc:write_special_name_constructor` writes it. */
        private val STRUCTOR_CODE = Regex("""CI[12]|C[1-4]|D[0124]""")

        /**
         * The variant [symbolName] is (`_ZN3FooC2Ev`: [BASE_CTOR]), or null. The demangler prints every
         * variant alike, so this finds the code where the name, cut there and closed as `C1Ev` or `D1Ev`,
         * still demangles to the same structor; a `C1` inside a name or a parameter does not.
         */
        fun of(symbolName: String): ItaniumStructor? {
            val fn = Demangler.of(symbolName) as? DemangledFunction ?: return null
            return STRUCTOR_CODE.findAll(symbolName).firstNotNullOfOrNull { code ->
                val stub = symbolName.substring(0, code.range.first) + (if (code.value[0] == 'D') "D1Ev" else "C1Ev")
                val probe = Demangler.of(stub) as? DemangledFunction
                val cls = fn.namespace ?: return@firstNotNullOfOrNull null
                // An inheriting constructor demangles under its base's name (`_ZN1BCI21AEi` is `B::A(int)`).
                val sameName = probe?.name == fn.name || code.value.startsWith("CI")
                byCode[code.value].takeIf {
                    probe != null && sameName && probe.namespace?.namespaceString == cls.namespaceString &&
                        // A structor takes its class's name, less template arguments and ABI tags.
                        probe.name.removePrefix("~") == cls.name.substringBefore('<').substringBefore("[abi:")
                }
            }
        }
    }
}

/** What an Itanium special name ([Itanium.specialName]) is. */
enum class SpecialName {
    /** A `_ZTV` vtable, `_ZTT` VTT or `_ZTC` construction vtable. */
    VTABLE,

    /** A `_ZTh`/`_ZTv`/`_ZTc` `this`-adjusting thunk, which Ghidra makes a plain function. */
    THUNK,

    /** A `_ZTI` typeinfo object or the `_ZTS` name string it points at. */
    TYPEINFO,

    /** Any other: a `_ZG` guard variable or reference temporary. */
    OTHER,
}

/** The `__cxxabiv1` class a class's typeinfo object is an instance of. */
enum class TypeinfoKind(private val abiClass: String) {
    /** `__class_type_info`: no bases. */
    CLASS(Itanium.CLASS_TYPE_INFO),

    /** `__si_class_type_info`: one public, non-virtual base at offset 0. */
    SI(Itanium.SI_CLASS_TYPE_INFO),

    /** `__vmi_class_type_info`: anything else, each base with its own offset and flags. */
    VMI(Itanium.VMI_CLASS_TYPE_INFO),
    ;

    companion object {
        /** The kind whose vtable is [vtableClass]'s, or null for any other class's. */
        fun ofVtableClass(vtableClass: String) = entries.firstOrNull {
            "${Itanium.ABI_NAMESPACE}::${it.abiClass}" == vtableClass
        }
    }
}

/** A typeinfo object's label: its `_ZTI` linkage name, or the demangler's `typeinfo` for it. */
val Symbol.isTypeinfo get() = Itanium.looksLikeZti(name) || name == ClassNaming.TYPEINFO

/** The class this is the typeinfo of: by its linkage name, an external's imported one, or its `typeinfo` label. */
val Symbol.typeinfoClass: String? get() = linkageNames.firstNotNullOfOrNull(Itanium::typeinfoClassOf)
    ?: classOfLabel(ClassNaming.TYPEINFO)

/** The class this is the vtable of, as [typeinfoClass] reads a typeinfo. */
val Symbol.vtableClass: String? get() = linkageNames.filter(Itanium::looksLikeVtable)
    .firstNotNullOfOrNull { Demangler.of(it)?.let(Itanium::demangledVtableClass) }
    ?: classOfLabel(ClassNaming.VTABLE)

private val Symbol.linkageNames get() = listOfNotNull(
    name,
    program.externalManager.getExternalLocation(this)?.originalImportedName.takeIf { isExternal },
)

private fun Symbol.classOfLabel(label: String) = parentNamespace.takeIf { name == label && !it.isGlobal }?.getName(true)
