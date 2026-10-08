package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.StabsImporter
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.defaultContext
import ghistabs.test.must
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * The bytes that round a struct up to its alignment are padding, not a hole: `_TAPE_SET_POSITION` ends
 * with 7 of them after its one-byte `Immediate`, which its `LARGE_INTEGER` aligns at 8. A struct with
 * nothing defined is still reported.
 */
@Tag("integration")
class TailPaddingHolesIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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

    private fun mostlyUndefined(vararg structs: String): List<String> {
        val stabs = listOf(
            "char:t(0,3)=r(0,3);0;127;",
            "long long unsigned int:t(0,6)=@s64;r(0,6);0000000000000;01777777777777777777777;",
        ) + structs
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "pad.c")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val ctx = builder.program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))
        return ctx.diagnostics.degradationTargets()["struct-mostly-undefined"].orEmpty().toList()
    }

    @Test
    fun trailingPaddingIsNotAHole() {
        mostlyUndefined("Tail:T(0,10)=s16q:(0,6),0,64;c:(0,3),64,8;;")
            .must("Tail's 7 trailing bytes are padding") { none { it.endsWith("/Tail") } }
    }

    @Test
    fun aStructWithNothingDefinedIsReported() {
        mostlyUndefined("Blank:T(0,10)=s8;;")
            .must("Blank has nothing but undefined bytes") { any { it.endsWith("/Blank") } }
    }
}
