package ghistabs.cpp.abi.itanium

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
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
 * `features/hello.cc` under gcc 12 with its stabs removed, through the whole analysis: the class pass lays each
 * class struct off the Itanium RTTI and vtables. `Up` and `Down` derive virtually from `Core`, and `Both` from
 * them.
 */
@Tag("integration")
class ItaniumClassStructsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `a virtual base is laid where its vtable's vbase offset says`() = withAnalyzed { program ->
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

    private fun Program.layout(cls: String) =
        (dataTypeManager.getDataType("/ClassDataTypes/$cls/$cls") as Structure).definedComponents
            .map { it.offset to "${it.fieldName}: ${it.dataType.name}" }

    private fun withAnalyzed(check: (Program) -> Unit) =
        withProgram(File(FeatureFixtureTest.FEATURES, "hello_elf_gcc12_nostabs")) { program ->
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(TaskMonitor.DUMMY)
                mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
            }
            check(program)
        }
}
