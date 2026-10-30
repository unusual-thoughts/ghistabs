package ghistabs.cpp

import ghidra.program.model.symbol.Namespace

/** A class with no namespace, deriving from [bases] and theirs. */
class TestClass(override val name: String, vararg bases: TestClass) : ClassDecl {
    override val ns: Namespace? = null
    override val ancestors: Set<ClassDecl> = bases.flatMapTo(mutableSetOf()) { it.ancestors + it }

    override fun toString() = name
}
