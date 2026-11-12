package ghicpp.recover

import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassNaming
import ghicpp.analyzers.GenericVftableAnalyzer
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.LoadedProgram
import ghidrakt.loadProgram
import ghidrakt.runTransaction
import ghistabs.integration.FeatureFixtureTest
import ghistabs.test.mustBe
import ghistabs.test.mustBeTrue
import org.junit.jupiter.api.*
import java.io.File

/**
 * `features/hello.cc` under gcc 13, x86-64, `-fno-rtti` and stripped, through the whole analysis with
 * *Vftables from pointer tables* on: no vtable has an rtti word nor a symbol, so only their shape finds them.
 * The address points below are those of the unstripped build's `_ZTV` symbols.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class GenericVftableFixtureIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program: Program get() = loaded.program

    @BeforeAll
    fun analyze() {
        loaded = loadProgram(File(FeatureFixtureTest.FEATURES, FIXTURE), "gcc")
        program.runTransaction("enable") {
            program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean(GenericVftableAnalyzer.NAME, true)
        }
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(TaskMonitor.DUMMY)
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
        }
    }

    @AfterAll
    fun close() {
        if (::loaded.isInitialized) loaded.close()
    }

    private fun addr(offset: Long): Address = program.imageBase.add(offset)

    /** The address of each table seeded, by its offset from the image base, with its slot count. */
    private fun seeded(): Map<Long, Int> = program.symbolTable.getSymbols(ClassNaming.VFTABLE)
        .let { it as Iterator<Symbol> }.asSequence()
        .filter { it.parentNamespace.name.startsWith(GenericVftableFinder.SEEDED_CLASS_PREFIX) }
        .associate { it.address.subtract(program.imageBase) to program.listing.getDataAt(it.address).numComponents }

    @Test
    fun `every vtable a constructor stores is seeded with its slots, and no GOT entry it loads`() {
        seeded() mustBe mapOf(
            0x6930L to 4, // Circle
            0x6960L to 3, // Secret
            0x6988L to 3, // Logger
            0x69b8L to 3, // Both
            0x69e8L to 3, // Both, for Down
            0x6a20L to 3, // Both, for Core
            0x6b58L to 3, // Down
            0x6b90L to 3, // Down, for Core
            0x6bc8L to 3, // Core
            0x6bf0L to 5, // Label
            0x6c28L to 2, // Label, for Named
            0x6c48L to 5, // Rect
            0x6c88L to 2, // Diamond
            0x6cc0L to 2, // Diamond, for Named
            0x6d00L to 2, // Named
            0x6d20L to 4, // Shape
        )
    }

    @Test
    fun `an abstract class's table opens on its null destructor slots, then its pure virtual`() {
        val shape = program.listing.getDataAt(addr(SHAPE))
        (shape.dataType is Structure).mustBeTrue()
        val targets = (0 until shape.numComponents).map { shape.getComponent(it) }
        targets.map { (it.value as Address).offset }.take(2) mustBe listOf(0L, 0L)
        targets.all { it.dataType is Pointer }.mustBeTrue()
        program.functionManager.getFunctionAt(targets[2].value as Address).getThunkedFunction(true).name mustBe
            "__cxa_pure_virtual"
    }

    @Test
    fun `a class derives from the one whose table its constructor's call stores or whose slots it shares`() {
        val symbols = program.symbolTable
        fun table(id: Long?) = id?.let { symbols.getSymbol(it) }?.let { cls ->
            symbols.getSymbols(cls.`object` as ghidra.program.model.symbol.Namespace).iterator().asSequence()
                .first { it.name == ClassNaming.VFTABLE }.address.subtract(program.imageBase)
        }
        val bases = program.readClassRecord().orEmpty().entries
            .filter { (_, e) -> e.bases.isNotEmpty() }
            .associate { (id, e) -> table(id) to e.bases.map { table(it.namespaceId) } }
        // Each primary table only: a base at an offset, as Label's Named and every virtual one, goes unseen.
        bases mustBe mapOf(
            0x6930L to listOf(SHAPE), // Circle
            0x6960L to listOf(0x6988L), // Secret : Logger
            0x6bf0L to listOf(0x6c48L), // Label : Rect
            0x6c48L to listOf(SHAPE), // Rect
        )
    }

    private companion object {
        const val FIXTURE = "hello_elf64_gcc13_nortti_stripped"
        const val SHAPE = 0x6d20L
    }
}
