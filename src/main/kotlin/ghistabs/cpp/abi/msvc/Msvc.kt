package ghistabs.cpp.abi.msvc

import ghidra.app.cmd.data.rtti.Rtti3Model
import ghidra.app.util.datatype.microsoft.DataValidationOptions
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.Namespace
import ghistabs.cpp.*
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.Structor
import ghistabs.cpp.abi.StructorRole
import ghistabs.cpp.abi.VtableRecord
import ghistabs.namespaces

/**
 * The Microsoft Visual C++ ABI: its `??` special names, and the labels Ghidra's RTTI analyzer puts on the
 * RTTI, which [ghistabs.cpp.abi.msvc.MsvcClasses] reads. No compiler that emits stabs uses it.
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

    /** A virtual base (clang's `IsVirtual`). Not a set pDisp, which a base inside a virtual one has too. */
    const val BCD_VBOFCONTOBJ = 0x10

    /** `??_7` labels the address point; the meta pointer in front is no part of the record. */
    override fun recordAt(program: Program, at: Address) = VtableRecord(at, null, this)

    /** The offset of the subobject the record serves, by its complete object locator. */
    override fun vfptrOffsetOf(record: VtableRecord, program: Program) =
        program.msvcSubobjectOffset(record.address)?.toLong()

    override val assignmentOperatorName = "operator="

    override val constructorsReturnThis get() = true

    override val mangledOperatorNew get() = setOf("??2@YAPAXI@Z", "??2@YAPEAX_K@Z")

    override val mangledOperatorDelete get() = setOf(
        "??3@YAXPAX@Z",
        "??3@YAXPEAX@Z",
        "??3@YAXPAXI@Z",
        "??3@YAXPEAX_K@Z",
    )

    /** The constructor, destructor, or deleting destructor, scalar unless it tests the vector flag. */
    override fun structorFor(role: StructorRole, func: Function) = when (role) {
        StructorRole.CONSTRUCTOR -> MsvcStructor.CONSTRUCTOR

        StructorRole.DESTRUCTOR -> MsvcStructor.DESTRUCTOR

        StructorRole.DELETING_DESTRUCTOR -> when {
            func.testsVectorFlag() -> MsvcStructor.VECTOR_DELETING_DESTRUCTOR
            else -> MsvcStructor.SCALAR_DELETING_DESTRUCTOR
        }
    }

    /** Whether this tests its flags for bit 2, which a vector deleting destructor does to free an array. */
    private fun Function.testsVectorFlag() = program.listing.getInstructions(body, true).any { insn ->
        insn.pcode.any { op -> op.opcode == PcodeOp.INT_AND && op.inputs.any { it.isConstant && it.offset == 2L } }
    }

    override fun isProbablyMangled(name: String) = name.startsWith("?")

    /** Off the class's Class Hierarchy Descriptor, which the RTTI analyzer labels in its namespace. */
    override fun basesOf(program: Program, cls: Namespace): List<BaseDecl>? =
        program.symbolTable.getSymbols(cls).firstOrNull { it.name == CLASS_HIERARCHY_DESCRIPTOR }?.let { chd ->
            runCatching { directBases(Rtti3Model(program, chd.address, DataValidationOptions()).baseClassArray()) }
                .getOrNull()
        }

    override fun looksLikeVtable(symbolName: String) = symbolName.startsWith(VFTABLE_PREFIX)

    /** A template's name has no closed form, as its arguments mangle as types. */
    override fun vtableCandidates(className: String) = listOfNotNull(
        "$VFTABLE_PREFIX${mangleClassName(className)}6B@".takeUnless { className.isTemplated },
        className.member(ClassNaming.VFTABLE),
    )

    /** Ghidra demangles `??_7` as `` `vftable' `` in the class's namespace. */
    override fun demangledVtableClass(obj: DemangledObject) =
        obj.namespaces.qualifiedName.takeIf { obj.name.trim('`', '\'') == ClassNaming.VFTABLE && it.isNotEmpty() }

    /** By its code (`??0`, `??_G`), whichever class it is in. */
    override fun structorOf(mangled: String, className: String?) = MsvcStructor.entries.firstOrNull {
        mangled.startsWith(it.code)
    }

    /** `a::b::Foo` as MSVC mangles a class name: `Foo@b@a@@`. Not for templates. */
    fun mangleClassName(name: String) = name.nameSegments.reversed().joinToString("") { "$it@" } + "@"
}

/**
 * An MSVC constructor or destructor, by its special name. A class with virtual bases builds them in its
 * one constructor, behind a flag, and destroys them in [VBASE_DESTRUCTOR].
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

    /** The vftable slot that destroys and frees one object. */
    SCALAR_DELETING_DESTRUCTOR("??_G", true, true, "`scalar_deleting_destructor'"),

    /** The vftable slot that destroys and frees an array instead when its flags have bit 2 set. */
    VECTOR_DELETING_DESTRUCTOR("??_E", true, true, "`vector_deleting_destructor'"),
    ;

    /** The source's name, or for a compiler-made function the one Ghidra's demangler gives it. */
    override fun displayName(className: String) =
        demangled ?: if (isDestructor) "~${className.leafName}" else className.leafName
}
