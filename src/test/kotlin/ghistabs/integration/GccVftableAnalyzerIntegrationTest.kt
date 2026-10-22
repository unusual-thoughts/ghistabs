package ghistabs.integration

import ghidra.app.util.NamespaceUtils
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.reloc.Relocation
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.DtmRegistry
import ghistabs.buildClassNamespaces
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.VtableSweeper
import ghistabs.cpp.abi.VtableSweeper.Companion.isVtablesSwept
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.entrypoints.GccVftableAnalyzer
import ghistabs.runTransaction
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustNot
import ghistabs.test.mustNotBeNull
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

    /** The label a class's own `VtableRecord.lay` leaves is the claim: the sweep must not lay that table again. */
    @Test
    fun leavesATableAClassLaid() {
        program.runTransaction("class-pass") {
            val ns = program.symbolTable.buildClassNamespaces(listOf("Foo"))
            program.symbolTable.createLabel(addressPoint, ClassNaming.VFTABLE, ns, SourceType.IMPORTED)
        }
        runAnalyzer().mustBe(true)
        program.fooVftable().mustBe(null, "swept a table a class had claimed")
    }

    /** Stabs not imported yet are no reason to wait: the import, once it runs, has the table swept again. */
    @Test
    fun sweepsWithoutWaitingForTheStabsImport() {
        builder.createMemory(".stab", "0x403000", 4)
        builder.createMemory(".stabstr", "0x404000", 4)

        runAnalyzer().mustBe(true)
        program.fooVftable().mustNotBeNull("not swept ahead of the stabs import")
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
     * Under the leaf alone shift-D finds no `Bar` namespace and skips them. Its typeinfo is blank, so
     * no base is known for either: numbered as Ghidra numbers them, labels left as they are.
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
        val primary = dtm.getDataType(category, "Bar_vftable0") as? Structure
        primary.mustNotBeNull("no ns::Bar vftable under $category")
        val secondary = dtm.getDataType(category, "Bar_vftable1") as? Structure
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

    /**
     * A dynamic link's imports, as the ELF loader lays them: a label in an EXTERNAL block with no bytes,
     * and for a function a thunk there to the external location.
     */
    private fun externalBlock(): Int {
        val external = 0x410000
        program.runTransaction("external") {
            val space = program.addressFactory.defaultAddressSpace
            program.memory.createUninitializedBlock("EXTERNAL", space.getAddress(external.toLong()), 0x100, false)
        }
        return external
    }

    private fun importFunction(name: String, at: Int) = program.runTransaction("import $name") {
        val ext = program.externalManager.addExtFunction("libstdc++.so.6", name, null, SourceType.IMPORTED)
        val addr = program.addressFactory.defaultAddressSpace.getAddress(at.toLong())
        program.functionManager.createThunkFunction(
            name,
            program.globalNamespace,
            addr,
            AddressSet(addr),
            ext.function,
            SourceType.IMPORTED,
        )
    }

    /** The loader's record of the word at [at] relocated against [symbol]. */
    private fun relocate(at: Int, symbol: String) = program.runTransaction("relocate") {
        val addr = program.addressFactory.defaultAddressSpace.getAddress(at.toLong())
        program.relocationTable.add(addr, Relocation.Status.APPLIED, 1, null, 4, symbol)
    }

    /**
     * gcc 12's `tinyxml2::MemPool` in xmltest: abstract, its destructor slots left 0 and the rest
     * `__cxa_pure_virtual`, an import. `{0, &_ZTI…, 0, 0, pure, pure}`, then a word that holds the same
     * address relocated against a data import, a typeinfo's vptr: not a slot.
     */
    @Test
    fun laysAnAbstractClassOfNullsAndImports() {
        val pure = externalBlock()
        importFunction("__cxa_pure_virtual", pure)
        val ztv = 0x401040
        val zti = 0x401140
        builder.setBytes(hex(ztv), le(0) + le(zti) + le(0) + le(0) + le(pure) + le(pure) + le(pure))
        relocate(ztv + 16, "__cxa_pure_virtual")
        relocate(ztv + 20, "__cxa_pure_virtual")
        relocate(ztv + 24, "_ZTVN10__cxxabiv120__si_class_type_infoE")
        builder.createLabel(hex(ztv), "_ZTV4Pool")
        builder.createLabel(hex(zti), "_ZTI4Pool")

        runAnalyzer().mustBe(true)

        val vftable = program.dataTypeManager.getDataType(ClassNaming.vftableCategory(listOf("Pool")), "Pool_vftable")
        vftable.mustNotBeNull("no Pool_vftable swept")
        (vftable as Structure).definedComponents.map { it.fieldName }
            .mustBe(listOf("slot", "slot_1", "__cxa_pure_virtual", "__cxa_pure_virtual_1"))
    }

    /** `__class_type_info`'s vtable in a dynamic link is the shared library's: only its label is here. */
    @Test
    fun leavesAnImportedVtable() {
        builder.createLabel(hex(externalBlock()), "_ZTVN10__cxxabiv117__class_type_infoE")
        val logged = mutableListOf<String>()
        val sink = object : DiagnosticSink {
            override fun log(
                category: String,
                message: String?,
                level: Level,
                address: Address?,
                degrades: String?,
                count: Long,
            ) {
                logged += category
            }
        }

        val sweeper = VtableSweeper(DtmRegistry(program.dataTypeManager), program, TaskMonitor.DUMMY, sink)
        program.runTransaction("sweep") { sweeper.sweepUnclaimedVtables() }.mustBe(1)
        logged.mustNot("swept the import") { contains("vtable-swept-empty") }
    }

    /** What `RecoveredClassHelper.getClassNamespace` makes of [vftable]'s category. */
    private fun Program.namespaceOf(vftable: Structure) =
        vftable.categoryPath.path.removePrefix(ClassNaming.classDataTypesRoot.path + "/").replace("/", "::")
            .let { NamespaceUtils.getNamespaceByPath(this, null, it) }
            .firstOrNull { !it.isExternal }
}
