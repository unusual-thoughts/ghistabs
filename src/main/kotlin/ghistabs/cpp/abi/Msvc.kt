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

    override fun stride(ptrSize: Int) = ptrSize.toLong()
    override fun pfnOffset(ptrSize: Int) = 0L

    /** The meta pointer to the complete object locator, which is where a `{vfptr}` points past. */
    override fun headerBytes(ptrSize: Int) = ptrSize.toLong()

    override val hasRttiHeader get() = true
    override val vptrAtRecordStart get() = false

    override val assignmentOperatorName = "operator="

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
