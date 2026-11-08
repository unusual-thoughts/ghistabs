package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.runOnRecords
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
            "int:t(0,1)=r(0,1);-2147483648;2147483647;",
            "char:t(0,3)=r(0,3);0;127;",
            "long long unsigned int:t(0,6)=@s64;r(0,6);0000000000000;01777777777777777777777;",
        ) + structs
        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "pad.c")) +
            stabs.mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        val ctx = builder.program.defaultContext()
        ctx.runOnRecords(StabReader.Result(records))
        return ctx.diagnostics.degradationTargets()["struct-mostly-undefined"].orEmpty().toList()
    }

    @Test
    fun trailingPaddingIsNotAHole() {
        mostlyUndefined("Tail:T(0,10)=s16q:(0,6),0,64;c:(0,3),64,8;;")
            .must("Tail's 7 trailing bytes are padding") { none { it.endsWith("/Tail") } }
    }

    @Test
    fun paddingToAnExplicitAlignmentIsNotAHole() {
        // `__attribute__((aligned))` rounds `_Unwind_Exception` from 20 bytes to 32, and CryptoPP's
        // `CRYPTOPP_ALIGN_DATA(8)` a byte allocator from 18 to 24: more padding than their widest scalar
        // explains, but less than the alignment the size itself implies. The stab carries no attribute.
        mostlyUndefined(
            "Unwound:T(0,10)=s32q:(0,6),0,64;a:(0,1),64,32;b:(0,1),96,32;c:(0,1),128,32;;",
            "Bytes:T(0,11)=s24arr:(0,12)=ar(0,1);0;15;(0,3),0,128;f:(0,3),128,8;g:(0,3),136,8;;",
        ).must("both tails are alignment padding") { none { it.endsWith("/Unwound") || it.endsWith("/Bytes") } }
    }

    @Test
    fun aTailLongerThanTheDataIsStillAHole() {
        // 16 bytes would allow 12 of padding after one int, but nothing pads more than it holds: a body
        // that lost its later members looks just like this.
        mostlyUndefined("Lost:T(0,10)=s16i:(0,1),0,32;;")
            .must("Lost's 12 trailing bytes are a hole") { any { it.endsWith("/Lost") } }
    }

    @Test
    fun aTailAfterAnUntypedFieldIsStillAHole() {
        // Fields whose type never resolved stand in at a guessed width, so what follows them may be the
        // rest of a field, not padding: x86-64's `__va_list_tag` lost the top half of `reg_save_area` so.
        mostlyUndefined("Vague:T(0,10)=s16a:(0,50),0,32;b:(0,50),32,32;c:(0,50),64,32;;")
            .must("Vague's 4 trailing bytes follow an untyped field") { any { it.endsWith("/Vague") } }
    }

    @Test
    fun aStructWithNothingDefinedIsReported() {
        mostlyUndefined("Blank:T(0,10)=s8;;")
            .must("Blank has nothing but undefined bytes") { any { it.endsWith("/Blank") } }
    }
}
