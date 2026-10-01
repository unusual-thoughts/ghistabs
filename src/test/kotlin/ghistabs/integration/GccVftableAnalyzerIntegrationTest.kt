package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.Structure
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.buildClassNamespaces
import ghistabs.entrypoints.GccVftableAnalyzer
import ghistabs.importer.ImportOptions.Companion.markStabsDone
import ghistabs.importer.VtableSweeper.Companion.isVtablesSwept
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [GccVftableAnalyzer] over one hand-built Itanium record, `_ZTV3Foo` = `{0, &_ZTI3Foo, Foo::a,
 * Foo::b}`, with no stabs to describe `Foo`: the symbols alone must give it a two-slot
 * `Foo_vftable` at the address point. With stab sections present it must leave the table to the
 * stabs import, and it must not sweep a program twice.
 */
@Tag("integration")
class GccVftableAnalyzerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private val ztv = 0x401000
    private val zti = 0x401100
    private val fooA = 0x402000
    private val fooB = 0x402100

    private val addressPoint get() = program.addressFactory.defaultAddressSpace.getAddress(ztv + 8L)

    private fun hex(v: Int) = "0x${v.toString(16)}"

    private fun le(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte(), (v shr 16).toByte(), (v shr 24).toByte())

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("vtable-sweep", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", hex(fooA), 0x200), true)
        builder.createEmptyFunction("_ZN3Foo1aEv", hex(fooA), 1, VoidDataType.dataType)
        builder.createEmptyFunction("_ZN3Foo1bEv", hex(fooB), 1, VoidDataType.dataType)

        // offset_to_top, rtti, the two slots, then a 0 that ends the function array.
        val record = le(0) + le(zti) + le(fooA) + le(fooB) + le(0)
        builder.createMemory(".rodata", hex(ztv), 0x200)
        builder.setBytes(hex(ztv), record)
        builder.createLabel(hex(ztv), "_ZTV3Foo")
        builder.createLabel(hex(zti), "_ZTI3Foo")
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun Program.fooVftable() =
        dataTypeManager.getDataType(ClassNaming.vftableCategory("Foo"), "Foo_vftable") as? Structure

    private fun runAnalyzer() = program.runTransaction("vtable-sweep") {
        GccVftableAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
    }

    @Test
    fun laysAVtableFromSymbolsAlone() {
        val analyzer = GccVftableAnalyzer()
        analyzer.must("a program with no stabs must be analyzable") { canAnalyze(program) }
        runAnalyzer().mustBe(true)

        val vftable = program.fooVftable()
        vftable.mustNotBeNull("no Foo_vftable swept")
        vftable!!.definedComponents.map { it.fieldName }.mustBe(listOf("a", "b"))

        program.listing.getDataAt(addressPoint)?.dataType?.name.mustBe("Foo_vftable")
        val label = program.symbolTable.getSymbols(addressPoint).single { it.name == ClassNaming.VFTABLE }
        label.getName(true).mustBe("Foo::${ClassNaming.VFTABLE}")
        // ANALYSIS, not IMPORTED: a class laying this table later has to be able to claim it.
        label.source.mustBe(SourceType.ANALYSIS)

        program.must("the sweep must mark the program swept") { isVtablesSwept }
        analyzer.mustNot("a swept program must not be swept again") { canAnalyze(program) }
    }

    /** The label a class's own `layVtable` leaves is the claim: the sweep must not lay that table again. */
    @Test
    fun leavesATableAClassLaid() {
        program.runTransaction("class-pass") {
            val ns = program.symbolTable.buildClassNamespaces(listOf("Foo"))
            program.symbolTable.createLabel(addressPoint, ClassNaming.VFTABLE, ns, SourceType.IMPORTED)
        }
        runAnalyzer().mustBe(true)
        program.fooVftable().mustBe(null, "swept a table a class had claimed")
    }

    @Test
    fun defersToTheStabsImport() {
        builder.createMemory(".stab", "0x403000", 4)
        builder.createMemory(".stabstr", "0x404000", 4)

        runAnalyzer().mustBe(false)
        program.fooVftable().mustBe(null, "swept ahead of the stabs import")

        // An import with this analyzer disabled marks the program imported but sweeps nothing.
        program.runTransaction("stabs-done") { program.markStabsDone(true) }
        runAnalyzer().mustBe(true)
        program.fooVftable().mustNotBeNull("not swept after an import that left it")
    }
}
