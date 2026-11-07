package ghistabs.cpp.abi.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghistabs.cpp.ClassBase
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.abi.VtableRecord

/**
 * A class its Itanium [typeinfo] describes: its bases off that typeinfo, and its virtual bases where the vbase
 * offsets of its [primary] vtable put them.
 */
abstract class TypeinfoClass(
    private val program: Program,
    private val reader: Rtti.Reader,
    private val typeinfo: Address?,
) : ClassDecl {
    /** The vtable the class's own vptr points into, if it has one. */
    protected abstract val primary: VtableRecord?

    /** The class of [base], one of this one's. */
    protected abstract fun classOf(base: Rtti.Reader.Base): ClassDecl

    override val bases by lazy {
        typeinfo?.let(reader::basesOf).orEmpty().map { b ->
            // A virtual base's offset is into the vtable, not the class.
            ClassBase(classOf(b), b.isVirtual, b.access, b.offset.takeUnless { b.isVirtual })
        }
    }

    override val virtualBases by lazy {
        val record = primary ?: return@lazy emptyList()
        typeinfo?.let(reader::virtualBasesOf).orEmpty().map { b ->
            ClassBase(classOf(b), isVirtual = true, b.access, record.vbaseOffset(program, b))
        }
    }
}
