package ghicpp.abi

import ghicpp.abi.itanium.Itanium
import ghidra.program.model.data.Structure
import ghidrakt.test.mustBe
import ghistabs.integration.FeatureFixtureTest
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

/**
 * A laid `vftable` struct ends at its table's last slot. gcc 3.3–4.9 link `.rodata` into the R-X text
 * segment, so every word there pointing back into `.rodata` passed for a function: a table ran on through
 * its padding into the next record (`offset_to_top` 0 as a null slot, then its typeinfo pointer) or into a
 * VTT, whose words point at other tables' address points.
 */
@Tag("integration")
class VftableExtentIntegrationTest : FeatureFixtureTest() {
    /**
     * No laid vftable struct holds a symbol past its start: the next `_ZTV`/`_ZTT`/`_ZTI`, or the `VTT` and
     * `vtable` labels the import put on them.
     */
    @ParameterizedTest
    @MethodSource("itaniumHellos")
    fun `a vftable struct stops before the next table`(fixture: String) {
        load(fixture)
        val overruns = program.listing.getDefinedData(true).iterator().asSequence()
            .filter { (it.dataType as? Structure)?.name?.contains("_vftable") == true }
            .flatMap { data ->
                program.symbolTable.getPrimarySymbolIterator(
                    program.addressFactory.getAddressSet(data.address.next(), data.maxAddress),
                    true,
                ).iterator().asSequence()
                    .map { "${data.dataType.name} at ${data.address} runs into ${it.name} at ${it.address}" }
            }.toList()
        overruns mustBe emptyList()
    }

    /**
     * gcc 4.1's `Rect` has five slots, and its table is followed by a padding word and `Both`'s VTT, whose
     * entries point at the address points of `Both`'s tables in `.rodata`.
     */
    @Test
    fun `Rect's vftable holds its five slots and no VTT entries`() {
        load("hello_elf_gcc41")
        val ztv = program.symbolTable.getSymbols("_ZTV4Rect").firstOrNull()?.address
        assumeTrue(ztv != null, "no _ZTV4Rect")
        val record = Itanium.recordAt(program, ztv!!)
        record.slots(program).size mustBe 5
        program.listing.getDataAt(record.addressPoint)?.length mustBe 5 * program.defaultPointerSize
    }

    companion object {
        @JvmStatic
        fun itaniumHellos() = stabsHellos().filter { "gcc2" !in it }
    }
}
