package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.WideCharDataType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.importer.runOnRecords
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
 * gcc 4.2.1 emits C++'s `wchar_t` as the range `short unsigned int` is, and Ghidra roots its own
 * `/wchar_t` (a WideCharDataType) as soon as anything demangles a `w`. The stab's name is that type.
 */
@Tag("integration")
class WcharIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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
    fun aWcharRangeIsGhidrasWchar() {
        val dtm = builder.program.dataTypeManager
        val tx = dtm.startTransaction("demangled wchar_t")
        dtm.resolve(WideCharDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER)
        dtm.endTransaction(tx, true)

        val records = listOf(StabRecord(0, StabType.N_SO, 0, 0, 0, "w.cpp")) +
            listOf("short unsigned int:t(0,10)=r(0,10);0;65535;", "wchar_t:t(0,21)=r(0,21);0;65535;")
                .mapIndexed { i, stab -> StabRecord(i + 1, StabType.N_LSYM, 0, 0, 0, stab) }
        builder.program.defaultContext().runOnRecords(StabReader.Result(records))

        dtm.allDataTypes.asSequence().filter { it.name.startsWith("wchar_t") }
            .map { "${it.pathName} ${it.javaClass.simpleName}" }.toList() mustBe listOf("/wchar_t WideCharDataType")
    }
}
