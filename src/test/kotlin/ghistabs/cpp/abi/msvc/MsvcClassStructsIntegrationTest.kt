package ghistabs.cpp.abi.msvc

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
 * `features/classes_msvc.cc` under the MSVC ABI, stripped: `Left` and `Right` derive virtually from `Core`, and
 * `Both` from them. No RTTI says where a virtual base sits: the vbtable does, which the constructors store
 * into the object next to its vftable, so the class pass finds it there and lays `Core` where it says.
 */
@Tag("integration")
class MsvcClassStructsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `a virtual base is laid where the vbtable a constructor stores says`() = withAnalyzed { program ->
        fun vbase(cls: String) = program.classStruct(cls).definedComponents.single { it.dataType.name == "Core" }
        vbase("Left").offset mustBe 12
        // Past the vtordisp `Right`'s override of `f` puts in front of it.
        vbase("Both").offset mustBe 28
    }

    @Test
    fun `a class with no vftable of its own at a fixed offset keeps its virtual base unplaced`() =
        withAnalyzed { program ->
            // `Right` adds no virtual, so its only vftable is `Core`'s, stored through the vbtable.
            program.classStruct("Right").definedComponents.none { it.dataType.name == "Core" } mustBe true
        }

    private fun Program.classStruct(name: String) =
        dataTypeManager.getDataType("/ClassDataTypes/$name/$name") as Structure

    private fun withAnalyzed(check: (Program) -> Unit) =
        withProgram(File(FeatureFixtureTest.FEATURES, FIXTURE), compiler = "windows") { program ->
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
    }
}
