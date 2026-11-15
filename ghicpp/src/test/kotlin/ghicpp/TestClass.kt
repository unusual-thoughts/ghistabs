package ghicpp

import ghicpp.abi.VtableRecord
import ghidra.program.model.symbol.Namespace

/** A class with no namespace, with direct [bases]. */
class TestClass(
    override val name: String,
    override val bases: List<ClassBase>,
    override val vftables: List<VtableRecord> = emptyList(),
    override val virtualBases: List<ClassBase> = emptyList(),
    private val unnamedVbaseOffsets: Set<Long> = emptySet(),
) : ClassDecl {
    /** A class deriving publicly from [bases], at offsets not known. */
    constructor(name: String, vararg bases: TestClass, vftables: List<VtableRecord> = emptyList()) :
        this(name, bases.map { ClassBase(it, false, Access.PUBLIC, null) }, vftables)

    override val ns: Namespace? = null

    override val vbaseOffsets get() = super.vbaseOffsets + unnamedVbaseOffsets

    override fun toString() = name
}

/** A public non-virtual base at [offset]. */
infix fun TestClass.at(offset: Long) = ClassBase(this, false, Access.PUBLIC, offset)

/** A public virtual base at [offset] in the complete object. */
infix fun TestClass.virtualAt(offset: Long) = ClassBase(this, true, Access.PUBLIC, offset)
