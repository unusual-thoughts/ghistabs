package ghistabs.cpp.abi.itanium

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.DoubleDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.ClassStructsFixtureTest
import ghistabs.entrypoints.ItaniumClassAnalyzer
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

    /** [cls]'s `<Class>_data` struct, a field per line: its offset, then its name and its type's. */
    private fun Program.data(cls: String) =
        (dataTypeManager.getDataType("/ClassDataTypes/$cls/${cls}_data") as Structure).definedComponents
            .map { it.offset to "${it.fieldName}: ${it.dataType.name}" }
}
