package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.Structure
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.StabsImporter
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.defaultContext
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A struct is as long as its stab's `s<size>`, which is gcc's sizeof for it, however far that lies
 * past its last field. Both shapes below were once trimmed to their last described byte.
 */
@Tag("integration")
class StabSizeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".text", "0x400000", 1024)
        builder.createMemory(".stab", "0x402000", 4)
        builder.createMemory(".stabstr", "0x403000", 4)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun lengthOf(name: String, vararg stabs: String): Int {
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "size.cpp")) +
            (listOf("int:t(0,1)=r(0,1);-2147483648;2147483647;", "char:t(0,3)=r(0,3);0;127;") + stabs)
                .mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val program = builder.program
        StabsImporter(program.defaultContext()).runOnRecords(StabReader.Result(records))
        return program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
            .single { it.name == name }.length
    }

    /**
     * xmltest_gcc421's `TiXmlText` is a 44-byte `TiXmlNode` of pointers and one `bool cdata` at +44,
     * padded to 48 by the base's alignment, which its own fields know nothing of.
     */
    @Test
    fun aDerivedClassIsPaddedToItsBasesAlignment() {
        lengthOf(
            "Derived",
            "Base:T(0,2)=s8a:(0,1),0,32;b:(0,1),32,32;;",
            "Derived:T(0,4)=s12!1,020,(0,2);c:(0,3),64,8;;",
        ) mustBe 12
    }

    /**
     * unwind.h's `_Unwind_Exception` is `__attribute__((__aligned__))`: 20 bytes of fields padded to
     * 32 on i386, which stabs has no way to say except by the size.
     */
    @Test
    fun anOverAlignedStructKeepsItsPadding() {
        lengthOf("Aligned", "Aligned:T(0,2)=s16a:(0,1),0,32;;") mustBe 16
    }
}
