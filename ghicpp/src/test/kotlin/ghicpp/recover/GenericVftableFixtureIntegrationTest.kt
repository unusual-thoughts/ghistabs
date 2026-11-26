package ghicpp.recover

import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.ClassNaming
import ghicpp.analyzers.GenericVftableAnalyzer
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.VirtualSlots
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.address.Address
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.test.TestBinaries
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeTrue
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
        loaded = loadProgram(File(TestBinaries.HELLOS, FIXTURE), "gcc")
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

    /** Each secondary table seeded, by its offset from the image base: its primary's, and its subobject's offset. */
    private fun secondaries(): Map<Long, Pair<Long, Long>> =
        program.symbolTable.getSymbolIterator(true).iterator().asSequence()
            .mapNotNull { sym -> ClassNaming.plainSubobjectOffset(sym.name)?.let { sym to it } }
            .filter { (sym, _) -> sym.parentNamespace.name.startsWith(GenericVftableFinder.SEEDED_CLASS_PREFIX) }
            .associate { (sym, offset) ->
                val primary = program.symbolTable.getSymbols(sym.parentNamespace).iterator().asSequence()
                    .first { it.name == ClassNaming.VFTABLE }
                sym.address.subtract(program.imageBase) to (primary.address.subtract(program.imageBase) to offset)
            }

    @Test
    fun `every primary vtable a constructor stores is seeded with its slots, and no GOT entry it loads`() {
        seeded() mustBe mapOf(
            0x6930L to 4, // Circle
            0x6960L to 3, // Secret
            0x6988L to 3, // Logger
            0x69b8L to 3, // Both
            0x6b58L to 3, // Down
            0x6a88L to 1, // Up, seeded off its construction table in Both: Up's own table no code stores
            0x6bc8L to 3, // Core
            0x6bf0L to 5, // Label
            0x6c48L to 5, // Rect
            0x6c88L to 2, // Diamond
            0x6d00L to 2, // Named
            0x6d20L to 4, // Shape
        )
    }

    /** Off the `offset_to_top` word in front of each, which is minus its subobject's offset. */
    @Test
    fun `a secondary vtable joins the class of the primary its group opens with, at its subobject's offset`() {
        secondaries() mustBe mapOf(
            0x69e8L to (0x69b8L to 16L), // Both, for Down
            0x6a20L to (0x69b8L to 32L), // Both, for its virtual Core
            0x6b90L to (0x6b58L to 16L), // Down, for its virtual Core
            0x6c28L to (0x6bf0L to 32L), // Label, for Named
            0x6cc0L to (0x6c88L to 32L), // Diamond, for Named
        )
    }

    @Test
    fun `an abstract class's table opens on its null destructor slots, then its pure virtual`() {
        val shape = program.listing.getDataAt(addr(SHAPE))
        (shape.dataType is Structure).mustBeTrue()
        val targets = (0 until shape.numComponents).map { shape.getComponent(it) }
        targets.map { (it.value as Address).offset }.take(2) mustBe listOf(0L, 0L)
        targets.all { it.dataType is Pointer }.mustBeTrue()
        program.functionManager.getFunctionAt(targets[2].value as Address).thunked?.name mustBe
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
        // A base at a nonzero offset is found from the class's secondary table there and the constructor called on
        // that subobject. Both's Up and Down are built by base-object constructors that take Both's VTT, and the
        // construction vtables it points at identify them.
        bases mustBe mapOf(
            0x6930L to listOf(SHAPE), // Circle
            0x6960L to listOf(0x6988L), // Secret : Logger
            0x69b8L to listOf(0x6b58L, 0x6a88L), // Both : Down, Up
            0x6b58L to listOf(0x6bc8L), // Down : virtual Core
            // Up : virtual Core, off the sub-VTT Both builds Up with: Up's own table no code stores.
            0x6a88L to listOf(0x6bc8L),
            0x6bf0L to listOf(0x6c48L, 0x6d00L), // Label : Rect, Named
            0x6c48L to listOf(SHAPE), // Rect
            0x6c88L to listOf(0x6d00L), // Diamond : Named, past its Left and Right, which have no table of their own
        )
    }

    @Test
    fun `a virtual base is laid where its secondary table puts it, as one`() {
        // Down derives virtually from Core. Down's own table for Core, at +16, replaces Core's vptr there. Because
        // Down is also a base of Both, Down's own fields get a struct of their own.
        val down = program.dataTypeManager.getDataType("/ClassDataTypes/Klass_00106b58/Klass_00106b58") as Structure
        down.definedComponents.map { "+${it.offset} ${it.fieldName}" } mustBe
            listOf("+0 vfptr", "+8 ${ClassNaming.FIELDS}", "+16 vfptr", "+24 _vbase_")
        down.getComponentAt(24).comment mustBe "virtual Klass_00106bc8 at +0x10, by its vftables"
    }

    /**
     * [VirtualSlots] over tables with no rtti word: Label's secondary table, labelled by its subobject's offset
     * alone (`vftable_for_base_at_32`), overrides Named's, the base at +32, so its slots root there.
     */
    @Test
    fun `a secondary table's slots override those of the base it is for`() {
        val hierarchy = ClassHierarchy.of(program, hasStabs = false)
        val slots = VirtualSlots(program, hierarchy)
        val label = hierarchy.classes.single { it.vftable == addr(0x6bf0L) }
        val forNamed = slots.slotsOf(label).filter { it.table == addr(0x6c28L) }
        forNamed.isNotEmpty().mustBeTrue("Label's table for Named: ${slots.slotsOf(label)}")
        forNamed.map { slots.root(it).table }.distinct() mustBe listOf(addr(0x6d00L))
    }

    private companion object {
        const val FIXTURE = "hello_elf64_gcc13_nortti_stripped"
        const val SHAPE = 0x6d20L
    }
}
