package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghistabs.get
import ghistabs.getScalar
import ghistabs.integration.FeatureFixtureTest
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.test.mustBe
import ghistabs.test.mustBeA
import ghistabs.test.mustBeTrue
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
class VtableRecordIntegrationTest : FeatureFixtureTest() {
    @ParameterizedTest
    @MethodSource("itaniumElfHellos")
    fun `a primary record's vbase offset is not taken for its offset_to_top`(fixture: String) {
        load(fixture)
        val ztv = program.symbolTable.getSymbols("_ZTV7Diamond").firstOrNull()?.address
        assumeTrue(ztv != null, "$fixture has no _ZTV7Diamond")
        val record = program.vtableRecord(ztv!!)

        record.prefixWords mustBe 1
        record.header?.name mustBe "VtableHeaderStructure1"
        with(Itanium) { record.vfptrOffset(program) } mustBe 0L
        program.rttiOf(record)
            ?.let { program.symbolTable.getSymbols(it) }
            .orEmpty().any { it.name == "_ZTI7Diamond" }
            .mustBeTrue("rtti word should point at _ZTI7Diamond")
        program.listing.getDataAt(ztv)?.get(VTABLE_OFFSETS)?.get(0)?.defaultValueRepresentation
            ?.endsWith("h").mustBe(false, "a laid vbase offset should render in decimal")
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
            .filter { it.name == ClassNaming.vftableLabel(true) && it.parentNamespace.name == "Diamond" }
            .map { it.address }.distinct().toList()

        val at = laid.singleOrNull().mustBeA<Address>("expected Named's secondary alone laid in Diamond, got $laid")
        val header = program.listing.getDataContaining(at.subtract(program.defaultPointerSize.toLong()))
        header?.dataType?.name mustBe "VtableHeaderStructure"
        header?.getScalar(Itanium.OFFSET_TO_TOP)?.signedValue mustBe -16L
        header?.get(Itanium.OFFSET_TO_TOP)?.defaultValueRepresentation mustBe "-16"
    }

    /**
     * `Diamond`'s typeinfo is a `__vmi_class_type_info` with one entry per direct base, whose offsets
     * read in decimal.
     */
    @ParameterizedTest
    @MethodSource("itaniumElfHellos")
    fun `vmi base offsets render in decimal`(fixture: String) {
        load(fixture)
        val zti = program.symbolTable.getSymbols("_ZTI7Diamond").firstOrNull()?.address
        assumeTrue(zti != null, "$fixture has no _ZTI7Diamond")
        val vmi = program.listing.getDataAt(zti!!)
        assumeTrue(vmi?.dataType?.name?.startsWith("VmiClassTypeInfoStructure") == true, "typeinfo not laid")

        val bases = vmi!![Rtti.BASES]
        val offsets = (0 until (bases?.numComponents ?: 0)).mapNotNull { bases?.get(it)?.get(Rtti.BASE_OFFSET) }
        offsets.isNotEmpty().mustBeTrue("expected base entries in $vmi")
        offsets.map { it.defaultValueRepresentation }.filter { it.endsWith("h") }
            .mustBe(emptyList(), "base offsets should render in decimal")
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
