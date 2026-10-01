package ghistabs.integration

import ghidra.app.util.NamespaceUtils
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.importer.VtableSweeper
import ghistabs.materialize.DtmRegistry
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [VtableSweeper] over a hand-built Itanium record with no stabs to describe its class: where the
 * tables it lays are filed, which is what Ghidra's class scripts read the class back from.
 */
@Tag("integration")
class VtableSweeperIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private fun hex(v: Int) = "0x${v.toString(16)}"

    private fun le(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte(), (v shr 16).toByte(), (v shr 24).toByte())

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("vtable-sweep", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x402000", 0x200), true)
        builder.createMemory(".rodata", "0x401000", 0x200)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun sweep() = program.runTransaction("vtable-sweep") {
        VtableSweeper(DtmRegistry(program.dataTypeManager), program, TaskMonitor.DUMMY).sweepUnclaimedVtables()
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

        sweep()

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
