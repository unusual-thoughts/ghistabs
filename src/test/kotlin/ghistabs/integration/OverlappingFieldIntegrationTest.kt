package ghistabs.integration

import ghidra.program.database.ProgramBuilder
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
 * gcc 2.6.3 flattens the union in its vtable entry, so iostream_test_aout_gcc263_fullstabs's stab puts
 * `__pfn` and `__delta2` both at +4. A struct holds one of them; the other is reported, not silently lost.
 */
@Tag("integration")
class OverlappingFieldIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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
    fun aFieldClearedByAnOverlappingOneIsReported() {
        val stabs = listOf(
            "int:t1=r1;-2147483648;2147483647;",
            "short int:t8=r8;-32768;32767;",
            "__vtbl_ptr_type:T18=s8__delta:8,0,16;__index:8,16,16;__pfn:19=*1,32,32;__delta2:8,32,16;;",
        )
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "vtbl.cc")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val ctx = builder.program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))

        ctx.diagnostics.degradationTargets()["field-overlapped"].orEmpty()
            .map { it.substringAfterLast('/') } mustBe listOf("__vtbl_ptr_type.__pfn")
    }
}
