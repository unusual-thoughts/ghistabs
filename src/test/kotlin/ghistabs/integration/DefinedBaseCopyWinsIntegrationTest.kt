package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.Structure
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
 * Two CUs' copies of one class, alike but for their base: `des.cpp` defines `DES::Base`, `modes.cpp` only
 * forward-declares it as `xsBase:`, and its other `Base` — `Rijndael::Base` — makes that tag ambiguous.
 * gcc 3.4 spells both bases as a field named for the class:
 * `ClonableImpl<…DES::Base>:T(0,42)=s160Base:(0,44),0,10240;;`. The copy whose base is defined is the one to lay.
 */
@Tag("integration")
class DefinedBaseCopyWinsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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
    fun theCopyWhoseBaseIsDefinedIsLaid() {
        val cus = listOf(
            "modes.cpp" to listOf(
                "int:t(0,1)=r(0,1);-2147483648;2147483647;",
                "Base:T(0,2)=s16c:(0,1),0,32;d:(0,1),32,32;e:(0,1),64,32;f:(0,1),96,32;;",
                "Clone:T(0,3)=s8Base:(0,4)=xsBase:,0,64;;",
            ),
            "des.cpp" to listOf(
                "int:t(0,1)=r(0,1);-2147483648;2147483647;",
                "Base:T(0,2)=s8a:(0,1),0,32;b:(0,1),32,32;;",
                "Clone:T(0,3)=s8Base:(0,2),0,64;;",
            ),
        )
        var index = 0
        val records = cus.flatMap { (cu, stabs) ->
            listOf(StabRecord(index++, StabType.N_SO, 0, 0, 0, cu)) +
                stabs.map { StabRecord(index++, StabType.N_LSYM, 0, 0, 0, it) }
        }
        val program = builder.program
        val ctx = program.defaultContext()
        ctx.runOnRecords(StabReader.Result(records))

        val clones = program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
            .filter { it.name == "Clone" }.toList()
        clones.must("one Clone, laid over des.cpp's 8-byte Base") {
            size == 1 && single().getComponentAt(0).dataType.let { it.name == "Base" && it.length == 8 }
        }
        ctx.diagnostics.degradationTargets()["base-synthesized"].orEmpty()
            .must("Clone's base is laid") { none { "Clone" in it } }
    }
}
