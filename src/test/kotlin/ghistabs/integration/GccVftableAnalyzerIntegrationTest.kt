package ghistabs.integration

import ghidra.app.util.NamespaceUtils
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
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
 * stabs import, and it must not sweep a program twice. A scoped class's tables go where Ghidra's class
 * scripts read its namespace back from.
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
        builder = ProgramBuilder("vtable-sweep", ProgramBuilder._X86, "gcc", this)
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
        dataTypeManager.getDataType(ClassNaming.vftableCategory(listOf("Foo")), "Foo_vftable") as? Structure

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

    /** An MSVC-built PE is not gcc's, however its symbols read: the Demangler analyzer's own test. */
    @Test
    fun leavesAWindowsProgramAlone() {
        val msvc = ProgramBuilder("msvc", ProgramBuilder._X86, "windows", this)
        try {
            GccVftableAnalyzer().mustNot("a windows program must not be analyzable") { canAnalyze(msvc.program) }
        } finally {
            msvc.dispose()
        }
        GccVftableAnalyzer().must("a gcc program must be analyzable") { canAnalyze(program) }
    }

    /**
     * `ns::Bar`, a primary and one secondary: both tables go under `/ClassDataTypes/ns/Bar/`, which
     * `RecoveredClassHelper.getClassNamespace` turns back into the namespace that holds their labels.
     * Under the leaf alone shift-D finds no `Bar` namespace and skips them.
     */
    @Test
    fun filesAScopedClassUnderItsNamespace() {
        val ztv = 0x401040
        val zti = 0x401140
        val (a, b, thunk) = listOf(0x402040, 0x402140, 0x402180)
        builder.createEmptyFunction("_ZN2ns3Bar1aEv", hex(a), 1, VoidDataType.dataType)
        builder.createEmptyFunction("_ZN2ns3Bar1bEv", hex(b), 1, VoidDataType.dataType)
        builder.createEmptyFunction("_ZThn8_N2ns3Bar1aEv", hex(thunk), 1, VoidDataType.dataType)
        // The primary {a, b}, then the secondary at -8 with the thunk, then the end of the record.
        builder.setBytes(hex(ztv), le(0) + le(zti) + le(a) + le(b) + le(-8) + le(zti) + le(thunk) + le(0))
        builder.createLabel(hex(ztv), "_ZTVN2ns3BarE")
        builder.createLabel(hex(zti), "_ZTIN2ns3BarE")

        runAnalyzer().mustBe(true)

        val category = ClassNaming.vftableCategory(listOf("ns", "Bar"))
        category.path.mustBe("/ClassDataTypes/ns/Bar")
        val dtm = program.dataTypeManager
        val primary = dtm.getDataType(category, "Bar_vftable") as? Structure
        primary.mustNotBeNull("no ns::Bar vftable under $category")
        val secondary = dtm.getDataType(category, "Bar_vftable_internal_0") as? Structure
        secondary.mustNotBeNull("no ns::Bar secondary under $category")
        // Its slot definitions keep a category of their own, or the thunk's would collide with `a`'s.
        val thunkSlot = secondary!!.definedComponents.mapNotNull { (it.dataType as? Pointer)?.dataType }
            .filterIsInstance<FunctionDefinition>().single()
        thunkSlot.categoryPath.mustBe(CategoryPath(category, "internal_0"))

        val addressPoint = program.addressFactory.defaultAddressSpace.getAddress(ztv + 8L)
        val label = program.symbolTable.getSymbols(addressPoint).single { it.name == ClassNaming.VFTABLE }
        program.namespaceOf(primary!!).mustBe(label.parentNamespace)
        program.namespaceOf(secondary).mustBe(label.parentNamespace)
    }

    /** What `RecoveredClassHelper.getClassNamespace` makes of [vftable]'s category. */
    private fun Program.namespaceOf(vftable: Structure) =
        vftable.categoryPath.path.removePrefix(ClassNaming.classDataTypesRoot.path + "/").replace("/", "::")
            .let { NamespaceUtils.getNamespaceByPath(this, null, it) }
            .firstOrNull { !it.isExternal }
}
