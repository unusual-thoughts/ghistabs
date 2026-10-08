package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.Structure
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.StabsImporter
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.defaultContext
import ghistabs.test.must
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A class's tail padding is bounded by its bases' fields too: xmltest_gcc421's `TiXmlText` is a 44-byte
 * `TiXmlNode` of pointers and one `bool cdata` at +44, padded to 48. Its own fields alone bound the
 * padding at 1 byte, which made the 3 trailing bytes look like an overshooting stab.
 */
@Tag("integration")
class BasePaddingIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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

    @Test
    fun aBaseFieldBoundsTheDerivedClassTailPadding() {
        val stabs = listOf(
            "int:t(0,1)=r(0,1);-2147483648;2147483647;",
            "char:t(0,3)=r(0,3);0;127;",
            "Base:T(0,2)=s8a:(0,1),0,32;b:(0,1),32,32;;",
            "Derived:T(0,4)=s12!1,020,(0,2);c:(0,3),64,8;;",
        )
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "pad.cpp")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val program = builder.program
        val ctx = program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))
        val derived = program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
            .single { it.name == "Derived" }

        derived.length mustBe 12
        ctx.diagnostics.degradationTargets()["struct-truncated"].orEmpty().must("Derived is not trimmed") { isEmpty() }
    }
}
