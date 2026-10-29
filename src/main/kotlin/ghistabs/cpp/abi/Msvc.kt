package ghistabs.cpp.abi

import ghidra.app.util.demangler.DemangledObject
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.isTemplated
import ghistabs.cpp.leafName
import ghistabs.cpp.member
import ghistabs.cpp.nameSegments
import ghistabs.cpp.qualifiedName
import ghistabs.namespaces

/**
 * Microsoft Visual C++ ABI facts: the `??_7` vftable spelling, the meta pointer in front of each
 * table, and the labels Ghidra's `Windows x86 PE RTTI Analyzer` puts on the RTTI it lays. [MsvcClasses]
 * reads that RTTI back into class records; nothing in the stabs import asks about this ABI, as no
 * compiler that emits stabs mangles this way.
 */
object Msvc : CxxAbi {
    /** A class's vftable: `??_7Foo@ns@@6B@` is `const ns::Foo::vftable`. */
    const val VFTABLE_PREFIX = "??_7"

    // The labels the RTTI analyzer gives each RTTI record, in the namespace of the class it describes.
    const val TYPE_DESCRIPTOR = "RTTI_Type_Descriptor"
    const val COMPLETE_OBJECT_LOCATOR = "RTTI_Complete_Object_Locator"
    const val CLASS_HIERARCHY_DESCRIPTOR = "RTTI_Class_Hierarchy_Descriptor"

    /** The pointer to a table's complete object locator, just before its first slot. */
    const val VFTABLE_META_PTR = "vftable_meta_ptr"

    // RTTIBaseClassDescriptor.attributes: the base is not visible from the most derived class, or is
    // a private or protected base (of it, or somewhere in the complete object). None says which.
    private const val BCD_NOTVISIBLE = 0x1
    private const val BCD_PRIVORPROTBASE = 0x4
    private const val BCD_PRIVORPROTINCOMPOBJ = 0x8
    const val BCD_NONPUBLIC = BCD_NOTVISIBLE or BCD_PRIVORPROTBASE or BCD_PRIVORPROTINCOMPOBJ

    /**
     * The base is virtual where the class that names it does: `BCD_VBOFCONTOBJ`, what clang's MSVC
     * emitter calls `IsVirtual`. Not its pDisp, which is set as well for a non-virtual base that sits
     * inside a virtual one.
     */
    const val BCD_VBOFCONTOBJ = 0x10

    override fun stride(ptrSize: Int) = ptrSize.toLong()
    override fun pfnOffset(ptrSize: Int) = 0L

    /** The meta pointer to the complete object locator, which is where a `{vfptr}` points past. */
    override fun headerBytes(ptrSize: Int) = ptrSize.toLong()

    override val hasRttiHeader get() = true
    override val vptrAtRecordStart get() = false

    override val assignmentOperatorName = "operator="

    override val constructorsReturnThis get() = true

    override val mangledOperatorNew get() = setOf("??2@YAPAXI@Z", "??2@YAPEAX_K@Z")

    /** What a vptr store makes of a function ([structors]): a deleting destructor is scalar until its flags say. */
    val storingStructors = StoringStructors(
        MsvcStructor.CONSTRUCTOR,
        MsvcStructor.DESTRUCTOR,
        MsvcStructor.SCALAR_DELETING_DESTRUCTOR,
    )

    override fun isProbablyMangled(name: String) = name.startsWith("?")

    override fun looksLikeVtable(symbolName: String) = symbolName.startsWith(VFTABLE_PREFIX)

    /** Templates have no closed form here either: their arguments mangle as types. */
    override fun vtableCandidates(className: String) = if (className.isTemplated) {
        listOf(className.member(ClassNaming.VFTABLE))
    } else {
        listOf("$VFTABLE_PREFIX${mangleClassName(className)}6B@", className.member(ClassNaming.VFTABLE))
    }

    /** Ghidra's demangler names a `??_7` symbol `` `vftable' `` in the class's namespace. */
    override fun demangledVtableClass(obj: DemangledObject) =
        obj.namespaces.qualifiedName.takeIf { obj.name.trim('`', '\'') == ClassNaming.VFTABLE && it.isNotEmpty() }

    /** `??0` mangles a constructor and `??1` a destructor, whichever class they are scoped to. */
    override fun specialMemberDisplayName(mangled: String, className: String) = when {
        mangled.startsWith("??0") -> className.leafName
        mangled.startsWith("??1") -> "~${className.leafName}"
        else -> null
    }

    /** `a::b::Foo` as the name a vftable or type descriptor spells it: `Foo@b@a@@`. Not for templates. */
    fun mangleClassName(name: String) = name.nameSegments.reversed().joinToString("") { "$it@" } + "@"
}

/**
 * A constructor or destructor by its MSVC special name. A class with virtual bases builds them in its
 * one constructor, behind a flag argument, and destroys them in a destructor of its own.
 */
enum class MsvcStructor(
    val code: String,
    override val isDestructor: Boolean,
    override val isDeleting: Boolean = false,
    private val demangled: String? = null,
) : Structor {
    CONSTRUCTOR("??0", false),

    /** Destroys all but the virtual bases. */
    DESTRUCTOR("??1", true),
    VBASE_DESTRUCTOR("??_D", true, demangled = "`vbase_destructor'"),

    /** The slot that destroys and frees one object. */
    SCALAR_DELETING_DESTRUCTOR("??_G", true, true, "`scalar_deleting_destructor'"),

    /** The slot that destroys an array of them instead when its flags argument has bit 2 set. */
    VECTOR_DELETING_DESTRUCTOR("??_E", true, true, "`vector_deleting_destructor'"),
    ;

    /** The source spelling, or for a special function the name Ghidra's demangler gives it. */
    override fun displayName(className: String) = demangled ?: if (isDestructor) "~$className" else className
}
