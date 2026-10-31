package ghistabs.cpp.abi.msvc

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.integration.FeatureFixtureTest
import ghistabs.runTransaction
import ghistabs.test.*
import ghistabs.withProgram
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * `features/classes_msvc.cc` under the MSVC ABI, stripped, through the whole analysis: the class pass lays
 * each class struct off the RTTI and the constructors. `Label` derives from `Rect`, itself a `Shape`, and
 * from `Named`; `Left` and `Right` derive virtually from `Core`, and `Both` from them.
 */
@Tag("integration")
class MsvcClassStructsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `each vptr is the class's own, typed to the table it points at, its bases split around it`() =
        withAnalyzed { program ->
            program.layout("Label") mustBe listOf(
                0 to "vfptr: Label_vftable_for_Rect *",
                4 to "_base_Rect: Rect_fields_4_16",
                16 to "vfptr: Label_vftable_for_Named *",
                20 to "_base_Named: Named_fields_4_8",
                24 to "Label_data: Label_data",
            )
            program.classStruct("Rect_vftable").definedComponents.map { it.fieldName } mustBe
                listOf("FUN_00401260", "vfunction2", "vfunction3")
        }

    @Test
    fun `a class's own fields are where its constructors store them`() = withAnalyzed { program ->
        program.classStruct("Rect_data").definedComponents.map { it.offset to it.fieldName } mustBe
            listOf(0 to "field_0x8", 4 to "field_0xc")
    }

    @Test
    fun `a virtual base is laid where the vbtable a constructor stores says`() = withAnalyzed { program ->
        program.layout("Left") mustBe listOf(
            0 to "vfptr: Left_vftable *",
            4 to "_fields: Left_fields_4_12",
            12 to "vfptr: Left_vftable_for_Core *",
            16 to "_vbase_: Core_fields_4_8",
        )
        // Past the vtordisp `Right`'s override of `f` puts in front of it.
        program.layout("Both").filter { (at, _) -> at >= 28 } mustBe listOf(
            28 to "vfptr: Both_vftable_for_Core *",
            32 to "_vbase_Core: Core_fields_4_8",
        )
    }

    @Test
    fun `a base with virtual bases is embedded as its non-virtual part, its vbptr in it`() = withAnalyzed { program ->
        program.layout("Both").first { (at, _) -> at == 4 } mustBe (4 to "_base_Left: Left_fields_4_12")
        val selfBase = program.dataTypeManager.getDataType("/ClassDataTypes/Left/Left/!internal/Left_fields_4_12")
        (selfBase as Structure).definedComponents.first().let { (it.fieldName to (it.dataType is Pointer)) } mustBe
            ("vbptr" to true)
    }

    @Test
    fun `a class whose only vftable is its virtual base's has the base laid off the vbtable`() =
        withAnalyzed { program ->
            // `Right` adds no virtual, so its only vftable is `Core`'s, stored through the vbtable.
            program.layout("Right") mustBe listOf(
                0 to "vbptr: int *",
                12 to "vfptr: Right_vftable *",
                16 to "_vbase_: Core_fields_4_8",
            )
        }

    @Test
    fun `a function several vftables hold has one definition, for signature updates to reach them all`() =
        withAnalyzed { program ->
            // `Left` inherits `Core::f`, its second slot in both tables.
            (program.secondSlot("Left_vftable_for_Core") === program.secondSlot("Core_vftable")) mustBe true
        }

    @Test
    fun `constructors the decompiler shows no this return for are told from destructors by their calls`() =
        withAnalyzed(HELLO) { program ->
            // clang's `-O0` callers leave the constructors' `this` return unread.
            program.layout("Circle") mustBe listOf(
                0 to "vfptr: Circle_vftable *",
                4 to "_base_: Shape_fields_4_16",
                16 to "Circle_data: Circle_data",
            )
        }

    private fun Program.secondSlot(table: String) = (classStruct(table).getComponent(1).dataType as Pointer).dataType

    private fun Program.classStruct(name: String) = dataTypeManager.allStructures.asSequence()
        .single {
            it.name == name && it.categoryPath.path.startsWith("/ClassDataTypes/") && "!internal" !in it.pathName
        }

    private fun Program.layout(cls: String) =
        (dataTypeManager.getDataType("/ClassDataTypes/$cls/$cls") as Structure).definedComponents
            .map { it.offset to "${it.fieldName}: ${it.dataType.name}" }

    private fun withAnalyzed(fixture: String = FIXTURE, check: (Program) -> Unit) =
        withProgram(File(FeatureFixtureTest.FEATURES, fixture), compiler = "windows") { program ->
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(TaskMonitor.DUMMY)
                mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
            }
            check(program)
        }

    private companion object {
        const val FIXTURE = "classes_msvc_clang.exe"
        const val HELLO = "hello_msvc_clang.exe"
    }
}
