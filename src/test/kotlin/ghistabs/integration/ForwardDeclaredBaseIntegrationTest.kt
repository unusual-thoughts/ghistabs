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
 * A base no CU defines: xapasmcsr's `CLexStream:Tt(1,309)=s328!1,020,(51,22);LineNo:/0(0,1),896,32;…`,
 * whose `(51,22)` is only ever `xsbasic_ifstream<char,std:…`. The 112 bytes before `LineNo` are the
 * base's, and the only size the binary gives it.
 */
@Tag("integration")
class ForwardDeclaredBaseIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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

    private fun import(vararg derived: String): Pair<List<Structure>, Map<String, List<String>>> {
        val stabs = listOf("int:t(0,1)=r(0,1);-2147483648;2147483647;", "Base:t(0,2)=xsBase:") + derived
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "fwd.cpp")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val program = builder.program
        val ctx = program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))
        val structs = program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>().toList()
        return structs to ctx.diagnostics.degradationTargets()
    }

    @Test
    fun aForwardDeclaredBaseTakesTheGapItsDerivedClassLeaves() {
        val (structs, degradations) = import("Derived:T(0,3)=s12!1,020,(0,2);a:(0,1),64,32;;")

        val derived = structs.single { it.name == "Derived" }
        derived.getComponentAt(0).dataType.must("Base, 8 bytes") { name == "Base" && length == 8 }
        derived.getComponentAt(8).fieldName mustBe "a"
        structs.filter { it.name.startsWith("Base") }.map { it.pathName }.must("one Base, no fork") { size == 1 }
        degradations["base-synthesized"].orEmpty().must("Base is laid") { isEmpty() }
        degradations["base-size-guessed"].orEmpty().must("the guess is reported") { size == 1 }
    }

    @Test
    fun aSecondDerivedClassWithASmallerGapLeavesItUndefined() {
        val (structs, degradations) = import(
            "Derived:T(0,3)=s12!1,020,(0,2);a:(0,1),64,32;;",
            "Other:T(0,4)=s8!1,020,(0,2);b:(0,1),32,32;;",
        )

        structs.single { it.name == "Base" }.length mustBe 8
        structs.single { it.name == "Other" }.getComponentAt(0).dataType.must("left undefined") { name != "Base" }
        degradations["base-synthesized"].orEmpty().must("reported") { any { it.endsWith("/Other@+0") } }
    }
}
