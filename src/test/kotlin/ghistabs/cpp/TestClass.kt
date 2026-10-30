package ghistabs.cpp

import ghidra.program.model.symbol.Namespace
import ghistabs.cpp.abi.VtableRecord

/** A class with no namespace, with direct [bases]. */
class TestClass(
    override val name: String,
    override val bases: List<ClassBase>,
    override val vftables: List<VtableRecord> = emptyList(),
) : ClassDecl {
    /** A class deriving publicly from [bases], at offsets not known. */
    constructor(name: String, vararg bases: TestClass, vftables: List<VtableRecord> = emptyList()) :
        this(name, bases.map { ClassBase(it, false, Access.PUBLIC, null) }, vftables)

    override val ns: Namespace? = null

    override fun toString() = name
}

/** A public non-virtual base at [offset]. */
infix fun TestClass.at(offset: Long) = ClassBase(this, false, Access.PUBLIC, offset)
