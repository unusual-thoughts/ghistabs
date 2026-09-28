package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.scalar.Scalar
import ghistabs.integration.FeatureFixtureTest
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.readAs
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

    /**
     * `Diamond : Left, Right, Named` has two secondaries under Itanium: `Right`'s at +8, which has no
     * virtuals and so no slots, then `Named`'s at +16 with its destructor thunks. The walk has to step
     * over the first to reach the second: one `internal_vftable` is laid in Diamond, and the record in
     * front of it says `offset_to_top` -16.
     */
    @ParameterizedTest
    @MethodSource("itaniumHellos")
    fun `a secondary behind a slotless one is still laid`(fixture: String) {
        load(fixture)
        // Cygwin's PE spells it with the leading underscore.
        val ztv = listOf("_ZTV7Diamond", "__ZTV7Diamond").firstNotNullOfOrNull {
            program.symbolTable.getSymbols(it).firstOrNull()
        }
        assumeTrue(ztv != null, "$fixture has no _ZTV7Diamond")
        val laid = program.symbolTable.symbolIterator.iterator().asSequence()
            .filter { it.name == ClassNaming.INTERNAL_VFTABLE && it.parentNamespace.name == "Diamond" }
            .map { it.address }.distinct().toList()

        val at = laid.singleOrNull().mustBeA<Address>("expected Named's secondary alone laid in Diamond, got $laid")
        val ptr = program.defaultPointerSize.toLong()
        program.readAs<Scalar>(at.subtract(2 * ptr), Itanium.offsetToTopType(program.defaultPointerSize))
            ?.signedValue mustBe -16L
    }

    companion object {
        @JvmStatic
        fun itaniumHellos() = FEATURES.list().orEmpty()
            .filter { it.startsWith("hello_") && "gcc2" !in it }
            .sorted()

        @JvmStatic
        fun itaniumElfHellos() = FEATURES.list().orEmpty()
            .filter { it.startsWith("hello_elf_") && "gcc2" !in it }
            .sorted()
    }
}
