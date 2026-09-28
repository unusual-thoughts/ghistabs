package ghistabs.materialize.cpp.abi

import ghistabs.integration.FeatureFixtureTest
import ghistabs.readPointer
import ghistabs.test.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

/**
 * `features/hello.cc`'s `Diamond` inherits `Base` virtually, so its primary record opens with one
 * vbase offset (0x20, where `Base` sits) before `offset_to_top` (0) and the rtti word. Two ways the
 * scan for that rtti word used to stop short, fall back to the two-word shape, and read the vbase
 * offset as `offset_to_top` with the address point a word early:
 *
 *  - gcc 3.3–4.9 link `.rodata` into the R-X text segment, so the rtti word points into executable
 *    memory the way a slot does, and ended the scan before it was looked at.
 *  - gcc ≥ 6 build PIE, which Ghidra loads at 0x10000. The loader has already relocated the words in
 *    memory; moving them by the stab base fixup as well sent every one of them past its target.
 */
@Tag("integration")
class VtableShapeIntegrationTest : FeatureFixtureTest() {
    @ParameterizedTest
    @MethodSource("itaniumElfHellos")
    fun `a primary record's vbase offset is not taken for its offset_to_top`(fixture: String) {
        load(fixture)
        val ztv = program.symbolTable.getSymbols("_ZTV7Diamond").firstOrNull()?.address
        assumeTrue(ztv != null, "$fixture has no _ZTV7Diamond")
        val shape = program.vtableShape(ztv!!)

        shape.prefix.size mustBe 1
        program.readPointer(shape.topSlot)?.offset mustBe 0L
        program.readPointer(shape.rttiHeader)
            ?.let { program.symbolTable.getSymbols(it) }
            .orEmpty().any { it.name == "_ZTI7Diamond" }
            .mustBeTrue("rtti word should point at _ZTI7Diamond")
    }

    companion object {
        @JvmStatic
        fun itaniumElfHellos() = FEATURES.list().orEmpty()
            .filter { it.startsWith("hello_elf_") && "gcc2" !in it }
            .sorted()
    }
}
