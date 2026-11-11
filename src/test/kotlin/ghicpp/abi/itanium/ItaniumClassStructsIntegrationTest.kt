package ghicpp.abi.itanium

import ghicpp.ClassNaming
import ghicpp.ClassStructsFixtureTest
import ghicpp.analyzers.ItaniumClassAnalyzer
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.VirtualSlots
import ghicpp.hierarchy.functionOf
import ghicpp.hierarchy.methodsOf
import ghicpp.hierarchy.resolve
import ghicpp.hierarchy.updateFieldTypes
import ghicpp.recover.updateFieldTypes
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.DoubleDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.runTransaction
import ghistabs.test.mustBe
import ghistabs.test.mustBeTrue
import org.junit.jupiter.api.Test

/**
 * `features/hello.cc` under gcc 12, stripped of its stabs and symbols, through the whole analysis: once
 * *Itanium RTTI symbols* has put back the labels, the class pass lays each class struct off the Itanium RTTI
 * and vtables. `Up` and `Down` derive virtually from `Core`, and `Both` from them.
 */
class ItaniumClassStructsIntegrationTest : ClassStructsFixtureTest("hello_elf_gcc12_stripped", compiler = "gcc") {
    @Test
    fun `every method the class passes place takes this, typed to its class, as __thiscall`() {
        val methods = program.functionManager.getFunctions(true).filter { it.parentNamespace is GhidraClass }
        methods.filter { f ->
            f.callingConventionName != CompilerSpec.CALLING_CONVENTION_thiscall ||
                f.getParameter(0)?.let { it.isAutoParameter && it.dataType.name == "${f.parentNamespace.name} *" } !=
                true
        }.map { "${it.getName(true)}: ${it.getPrototypeString(false, false)}" } mustBe emptyList()
    }

    @Test
    fun `a virtual base is laid where its vtable's vbase offset says`() {
        program.layout("Down") mustBe listOf(
            0 to "vfptr: Down_vftable0 *",
            4 to "_fields: Down_fields_4_8",
            8 to "vfptr: Down_vftable_for_Core *",
            12 to "_vbase_: Core_fields_4_8",
        )
        // `Up` and `Down` are embedded as their non-virtual parts, `Core` once, after them.
        program.layout("Both") mustBe listOf(
            0 to "vfptr: Both_vftable_for_Up *",
            4 to "_base_Up: Up_fields_4_8",
            8 to "vfptr: Both_vftable_for_Down *",
            12 to "_base_Down: Down_fields_4_8",
            16 to "Both_data: Both_data",
            20 to "vfptr: Both_vftable_for_Core *",
            24 to "_vbase_Core: Core_fields_4_8",
        )
    }

    /**
     * `Shape` is abstract: gcc 12 leaves its destructor slots 0 and points `area` at the imported
     * `__cxa_pure_virtual`, so its vtable has no slot 0 into code, and is still found.
     */
    @Test
    fun `an abstract class's vtable is found though its destructor slots are 0`() {
        val shape = program.symbolTable.getNamespace("Shape", program.globalNamespace)
        val labels = program.symbolTable.getSymbols(shape).map { it.name }
        (ClassNaming.VFTABLE in labels).mustBeTrue("no vftable among $labels")
    }

    /**
     * `Shape::name` is only ever called through the vtable, so nothing made a function at it. Its slot
     * names it, and the slot is typed off it.
     */
    @Test
    fun `a slot target no analysis made a function of becomes one`() {
        val name = program.addressFactory.defaultAddressSpace.getAddress(0x11be8)
        (program.functionManager.getFunctionAt(name) != null).mustBeTrue("no function at $name")
    }

    @Test
    fun `running the class pass again types a field off a constructor the reverser typed since`() {
        val ctors = program.functionManager.getFunctions(true).filter { it.getName(true) == "Circle::Circle" }
        program.runTransaction {
            for (ctor in ctors) {
                val r = ParameterImpl("r", DoubleDataType.dataType, program)
                ctor.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall)
                ctor.replaceParameters(DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED, r)
            }
            ItaniumClassAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
        }
        program.data("Circle") mustBe listOf(0 to "field_0x10: double")
    }

    @Test
    fun `updating field types from a method types the fields it reads`() {
        // `Label::area` returns `color`, which `Label::Label` stores a constant in.
        val area = program.methods("Label").single { it.name == "vfunction3_for_Rect" }
        program.runTransaction { program.updateFieldTypes(area.classNs, listOf(area), TaskMonitor.DUMMY) }
        program.data("Label") mustBe listOf(0 to "field_0x24: int")
    }

    @Test
    fun `updating field types from a class types the fields its methods use`() {
        // `Diamond::operator+=` adds to `d`, which `Diamond::Diamond` stores a constant in.
        val methods = program.methods("Diamond")
        program.runTransaction { program.updateFieldTypes(methods[0].classNs, methods, TaskMonitor.DUMMY) }
        program.data("Diamond") mustBe listOf(0 to "field_0x1c: int")
    }

    @Test
    fun `the window updates a class's field types from its own methods`() {
        val diamond = ClassHierarchy.of(program, hasStabs = false).classes.single { it.qualifiedName == "Diamond" }
        program.methodsOf(program.resolve(diamond)!!).map { it.entryPoint }.sorted() mustBe
            program.methods("Diamond").filterNot { it.isThunk }.map { it.entryPoint }.sorted()
        program.runTransaction { program.updateFieldTypes(diamond, null, TaskMonitor.DUMMY) }
        program.data("Diamond") mustBe listOf(0 to "field_0x1c: int")
    }

    @Test
    fun `the window updates a class's field types from a method selected`() {
        val label = ClassHierarchy.of(program, hasStabs = false).classes.single { it.qualifiedName == "Label" }
        val area = label.members.single { it.name == "vfunction3_for_Rect" }
        program.runTransaction {
            program.updateFieldTypes(label, listOf(program.functionOf(area)!!), TaskMonitor.DUMMY)
        }
        program.data("Label") mustBe listOf(0 to "field_0x24: int")
    }

    @Test
    fun `renaming a virtual slot renames every override of it, through a table for a base`() {
        val tx = program.startTransaction("rolled back")
        try {
            val h = ClassHierarchy.of(program, hasStabs = false)
            val slots = VirtualSlots(program, h)
            // `Rect::area`, after the two destructor slots: `Shape`'s pure one, `Circle`'s, and `Label`'s,
            // in its table for `Rect`.
            val area = slots.target(slots.slotsOf(h.classes.single { it.qualifiedName == "Rect" })[2])!!
            slots.rename(area, "area").functions mustBe 3
            for (cls in listOf("Circle", "Rect", "Label")) {
                slots.target(slots.slotsOf(h.classes.single { it.qualifiedName == cls })[2])!!.name mustBe "area"
            }
            val shape = program.dataTypeManager.getDataType("/ClassDataTypes/Shape/Shape_vftable") as Structure
            shape.getComponent(2).fieldName mustBe "area"
        } finally {
            program.endTransaction(tx, false)
        }
    }

    private fun Program.methods(cls: String) = functionManager.getFunctions(true).filter {
        it.parentNamespace.name == cls
    }

    private val Function.classNs get() = parentNamespace as GhidraClass

    /** [cls]'s `<Class>_data` struct, a field per line: its offset, then its name and its type's. */
    private fun Program.data(cls: String) =
        (dataTypeManager.getDataType("/ClassDataTypes/$cls/${cls}_data") as Structure).definedComponents
            .map { it.offset to "${it.fieldName}: ${it.dataType.name}" }
}
