package ghicpp.recover

import ghicpp.analyzers.GenericVftableAnalyzer
import ghicpp.analyzers.MethodClassAnalyzer
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DummySink
import ghidrakt.test.TestBinaries
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeTrue
import org.junit.jupiter.api.*
import java.io.File

/**
 * A one-time run of *Vftables from pointer tables* is followed by one of *Method classes from this* when that is
 * enabled, as auto-analysis follows the other, and by none when it is disabled. The program is
 * [GenericVftableFixtureIntegrationTest]'s, analyzed whole; each one-time test takes the method class guesses
 * back out first.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GenericVftableOneTimeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program: Program get() = loaded.program
    private val mgr get() = AutoAnalysisManager.getAnalysisManager(program)
    private val methodClasses get() = mgr.getAnalyzer(MethodClassAnalyzer.NAME) as MethodClassAnalyzer

    /** Each function auto-analysis guessed the class of, with that class's full name. */
    private lateinit var guessed: Map<Address, String>

    /** How many functions a second pass over auto-analysis's classes moved. */
    private var movedAgain = -1

    @BeforeAll
    fun analyze() {
        loaded = loadProgram(File(TestBinaries.HELLOS, FIXTURE), "gcc")
        program.runTransaction("enable") { program.setAnalyzerEnabled(GenericVftableAnalyzer.NAME) }
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(TaskMonitor.DUMMY)
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
        }
        guessed = guesses()
        guessed.isNotEmpty().mustBeTrue()
        movedAgain = program.runTransaction("again") { MethodClassPass(program, DummySink).run(TaskMonitor.DUMMY) }
    }

    @AfterAll
    fun close() {
        if (::loaded.isInitialized) loaded.close()
    }

    private fun guesses(): Map<Address, String> =
        program.bookmarkManager.getBookmarksIterator(BookmarkType.ANALYSIS).asSequence()
            .filter { it.category == MethodClassPass.BOOKMARK }
            .associate { b ->
                b.address to program.functionManager.getFunctionAt(b.address).parentNamespace.getName(true)
            }

    /** Put each guessed function back in the global namespace, its bookmark removed, and run the analyzer once. */
    private fun unguessThenRunOnce(methodClassesEnabled: Boolean) {
        program.runTransaction("unguess") {
            program.setAnalyzerEnabled(MethodClassAnalyzer.NAME, methodClassesEnabled)
            for (address in guessed.keys) {
                program.functionManager.getFunctionAt(address).parentNamespace = program.globalNamespace
                program.bookmarkManager.removeBookmarks(
                    AddressSet(address),
                    BookmarkType.ANALYSIS,
                    MethodClassPass.BOOKMARK,
                    TaskMonitor.DUMMY,
                )
            }
        }
        program.runTransaction("one time") {
            mgr.scheduleOneTimeAnalysis(mgr.getAnalyzer(GenericVftableAnalyzer.NAME), program.memory)
            mgr.startAnalysis(TaskMonitor.DUMMY)
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
        }
    }

    private fun runMethodClasses() = program.runTransaction("run") {
        methodClasses.added(program, program.memory, TaskMonitor.DUMMY, mgr.messageLog)
    }

    @Test
    fun `a run right after another, with nothing changed between, returns at once`() {
        runMethodClasses()
        methodClasses.isUpToDate(program).mustBeTrue()
        val before = program.modificationNumber
        runMethodClasses()
        program.modificationNumber mustBe before
    }

    @Test
    fun `a second pass over the same classes moves nothing`() {
        movedAgain mustBe 0
    }

    @Test
    fun `an edit by hand makes the next run look again`() {
        program.runTransaction("edit") { program.functionManager.getFunctionAt(guessed.keys.first()).comment = "x" }
        methodClasses.isUpToDate(program).mustBe(false)
    }

    @Test
    fun `a changed analysis option makes the next run look again`() {
        runMethodClasses()
        methodClasses.isUpToDate(program).mustBeTrue()
        program.runTransaction("option") {
            val options = program.analyzerOptions(GenericVftableAnalyzer.NAME)
            val member = GenericVftableAnalyzer.MEMBER_OBJECTS
            options.setBoolean(member.name, !options.getBoolean(member.name, member.default))
        }
        methodClasses.isUpToDate(program).mustBe(false)
    }

    @Test
    fun `a one-time run guesses no method class while Method classes from this is disabled`() {
        unguessThenRunOnce(methodClassesEnabled = false)
        guesses() mustBe emptyMap()
    }

    @Test
    fun `a one-time run is followed by Method classes from this while it is enabled`() {
        unguessThenRunOnce(methodClassesEnabled = true)
        guesses() mustBe guessed
    }

    private companion object {
        const val FIXTURE = "hello_elf64_gcc13_nortti_stripped"
    }
}
