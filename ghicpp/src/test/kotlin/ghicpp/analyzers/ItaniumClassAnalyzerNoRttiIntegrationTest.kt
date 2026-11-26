package ghicpp.analyzers

import ghicpp.ClassNaming
import ghicpp.abi.itanium.ItaniumRttiParser
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
 * *Itanium RTTI classes* on an ELF with no `typeinfo` labelled, as one built with `-fno-rtti`: it returns at once,
 * rather than going over the classes another analyzer made, as on a rerun after *Vftables from pointer tables*.
 * The program is `features/hello_elf64_gcc13_nortti_stripped` as loaded, before any analysis.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ItaniumClassAnalyzerNoRttiIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program: Program get() = loaded.program

    @BeforeAll
    fun load() {
        loaded = loadProgram(File(TestBinaries.HELLOS, "hello_elf64_gcc13_nortti_stripped"), "gcc")
    }

    @AfterAll
    fun close() {
        if (::loaded.isInitialized) loaded.close()
    }

    @Test
    fun `with no typeinfo labelled, it changes nothing`() {
        ItaniumRttiParser.hasRtti(program) mustBe false
        val before = program.modificationNumber
        val changed = program.runTransaction("run") {
            ItaniumClassAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
        }
        changed mustBe false
        program.modificationNumber mustBe before
    }

    @Test
    fun `a typeinfo label counts as RTTI`() {
        val id = program.startTransaction("label")
        try {
            program.symbolTable.createLabel(program.imageBase, ClassNaming.TYPEINFO, SourceType.ANALYSIS)
            ItaniumRttiParser.hasRtti(program) mustBe true
        } finally {
            program.endTransaction(id, false)
        }
    }
}
