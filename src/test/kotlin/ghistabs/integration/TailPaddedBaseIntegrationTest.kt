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
 * A deriving class's field in its base's tail padding, as the Itanium ABI lays a non-POD base: CryptoPP's
 * `CCM_Base` puts `m_digestSize` at +60, inside the 64 bytes of `AuthenticatedSymmetricCipherBase`, whose
 * data ends at 60. Here `Base` is 8 bytes whose data ends at 5, and `Derived` puts `c` at +5.
 */
@Tag("integration")
class TailPaddedBaseIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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

    private fun import(derived: String): Pair<Structure, Map<String, List<String>>> {
        val stabs = listOf(
            "int:t(0,1)=r(0,1);-2147483648;2147483647;",
            "char:t(0,3)=r(0,3);0;127;",
            "Base:T(0,2)=s8a:(0,1),0,32;b:(0,3),32,8;;",
            derived,
        )
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "tail.cpp")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val program = builder.program
        val ctx = program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))
        val struct = program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
            .single { it.name == "Derived" }
        return struct to ctx.diagnostics.degradationTargets()
    }

    @Test
    fun aBaseIsLaidAsItsDataWhenTheDerivedClassReusesItsTailPadding() {
        val (derived, degradations) = import("Derived:T(0,4)=s8!1,020,(0,2);c:(0,3),40,8;;")

        val base = derived.getComponentAt(0)
        base.dataType.must("Base's data, ending at 5") { name == "Base" && length == 5 }
        base.dataType.categoryPath.name mustBe "!internal"
        derived.getComponentAt(5).fieldName mustBe "c"
        degradations["base-synthesized"].orEmpty().must("Base is laid") { isEmpty() }
        degradations["struct-mostly-undefined"].orEmpty().must("Derived is filled") { isEmpty() }
    }

    @Test
    fun aBaseWhoseDataOverrunsTheGapIsLeftUndefined() {
        val (derived, degradations) = import("Derived:T(0,4)=s8!1,020,(0,2);c:(0,3),24,8;;")

        derived.getComponentAt(0).dataType.must("left undefined") { name != "Base" }
        degradations["base-synthesized"].orEmpty().must("reported") { any { it.endsWith("/Derived@+0") } }
    }
}
