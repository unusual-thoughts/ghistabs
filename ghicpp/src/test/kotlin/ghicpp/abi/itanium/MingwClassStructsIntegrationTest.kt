package ghicpp.abi.itanium

import ghicpp.ClassStructsFixtureTest
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

/**
 * `features/hello.cc` under MinGW gcc 4.2.1, stripped of its stabs and symbols, through the whole analysis:
 * with no stabs to describe its classes, the Itanium RTTI does, and their methods take `this` as gcc passes it.
 */
class MingwClassStructsIntegrationTest : ClassStructsFixtureTest("hello_gcc421_stripped.exe", compiler = "gcc") {
    private val methods get() = program.functionManager.getFunctions(true).filter { it.parentNamespace is GhidraClass }

    @Test
    fun `the RTTI's classes get their methods`() {
        val classes = methods.mapTo(sortedSetOf()) { it.parentNamespace.name }
        (listOf("Both", "Circle", "Core", "Down", "Up") - classes) mustBe emptyList()
    }

    /**
     * gcc's `long double` is ten bytes in ST0; `__thiscall` would hand it back through a hidden pointer, so a
     * method returning one keeps the storage it has.
     */
    @Test
    fun `every method but those returning a long double takes this, typed to its class, as __thiscall`() {
        val (longDouble, rest) = methods.partition { it.returnType.length == LONG_DOUBLE }
        rest.filterNot {
            it.takesTypedThis()
        }.map { "${it.getName(true)}: ${it.callingConventionName} ${it.getPrototypeString(false, false)}" }
            .mustBe(emptyList())
        longDouble.map { it.getName(true) }.sorted() mustBe
            listOf("Circle::vfunction3", "Label::vfunction3_for_Rect", "Rect::vfunction3")
    }

    private fun Function.takesTypedThis() = callingConventionName == CompilerSpec.CALLING_CONVENTION_thiscall &&
        getParameter(0)?.let { it.isAutoParameter && it.dataType.name == "${parentNamespace.name} *" } == true

    private companion object {
        const val LONG_DOUBLE = 10
    }
}
