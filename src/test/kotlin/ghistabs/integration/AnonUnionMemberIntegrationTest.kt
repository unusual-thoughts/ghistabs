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
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * oaidl.h's `tagVARIANT` as MinGW gcc 4.2 emits it: its only member is an unnamed union, gcc's `$_N`,
 * which each CU numbers on its own. Filed under its CU, that union may be filled after the struct that
 * holds it, so the struct's member is an empty placeholder until then.
 */
@Tag("integration")
class AnonUnionMemberIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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

    private fun variant(value: Int, inner: Int, outer: Int) = arrayOf(
        "int:t(0,1)=r(0,1);-2147483648;2147483647;",
        "\$_$value:T(0,5)=u4lVal:(0,1),0,32;pvarVal:(0,10)=*(0,11)=xstagVARIANT:,0,32;;",
        "\$_$inner:T(0,6)=s16vt:(0,1),0,32;:(0,5),64,32;;",
        "\$_$outer:T(0,7)=u16:(0,6),0,128;decVal:(0,8)=ar(0,1);0;3;(0,1),0,128;;",
        "tagVARIANT:T(0,11)=s16:(0,7),0,128;;",
    )

    @Test
    fun aStructIsCheckedForHolesOnceItsAnonymousUnionIsFilled() {
        var index = 0
        fun cu(name: String, vararg stabs: String) = listOf(StabRecord(index++, StabType.N_SO, 0, 0, 0, name)) +
            stabs.map { StabRecord(index++, StabType.N_LSYM, 0, 0, 0, it) }
        val records = cu("osrng.cpp", *variant(167, 166, 165)) +
            cu("hrtimer.cpp", *variant(165, 164, 163))
        val program = builder.program
        val ctx = program.defaultContext()
        StabsImporter(ctx).runOnRecords(StabReader.Result(records))

        val variant = program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
            .single { it.name == "tagVARIANT" }
        variant.getComponentAt(0).must("tagVARIANT's union spans all 16 bytes") { length == 16 }
        ctx.diagnostics.degradationTargets()["struct-mostly-undefined"].orEmpty()
            .must("tagVARIANT is reported as mostly undefined") { none { it.endsWith("/tagVARIANT") } }
    }
}
