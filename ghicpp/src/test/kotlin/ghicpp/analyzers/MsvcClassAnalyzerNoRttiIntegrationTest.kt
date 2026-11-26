package ghicpp.analyzers

import ghicpp.abi.msvc.Msvc
import ghicpp.abi.msvc.MsvcRttiParser
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.test.TestBinaries
import ghidrakt.test.mustBe
import org.junit.jupiter.api.*
import java.io.File

/**
 * *MSVC RTTI classes* on a PE no RTTI analyzer has laid records in, as one built without RTTI: it returns at
 * once, rather than going over the classes another analyzer made, as on a rerun after *Vftables from pointer
 * tables*. The program is `features/hello_msvc.exe` as loaded, before any analysis.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MsvcClassAnalyzerNoRttiIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program: Program get() = loaded.program

    @BeforeAll
    fun load() {
        loaded = loadProgram(File(TestBinaries.HELLOS, "hello_msvc.exe"), "windows")
    }

    @AfterAll
    fun close() {
        if (::loaded.isInitialized) loaded.close()
    }

    @Test
    fun `with no RTTI laid, it changes nothing`() {
        MsvcRttiParser.hasRtti(program) mustBe false
        val before = program.modificationNumber
        val changed = program.runTransaction("run") {
            MsvcClassAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
        }
        changed mustBe false
        program.modificationNumber mustBe before
    }

    @Test
    fun `a class hierarchy descriptor counts as RTTI`() {
        val id = program.startTransaction("label")
        try {
            program.symbolTable.createLabel(program.imageBase, Msvc.CLASS_HIERARCHY_DESCRIPTOR, SourceType.ANALYSIS)
            MsvcRttiParser.hasRtti(program) mustBe true
        } finally {
            program.endTransaction(id, false)
        }
    }
}
