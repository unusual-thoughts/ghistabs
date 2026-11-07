package ghistabs.cpp

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.LoadedProgram
import ghistabs.integration.FeatureFixtureTest
import ghistabs.loadProgram
import ghistabs.runTransaction
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.File

/**
 * A stripped [fixture] under `features/` through the whole analysis, once for all its tests: the class pass
 * lays each class struct off the RTTI and the constructors.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class ClassStructsFixtureTest(private val fixture: String, private val compiler: String) :
    AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    protected val program: Program get() = loaded.program

    @BeforeAll
    fun analyze() {
        loaded = loadProgram(File(FeatureFixtureTest.FEATURES, fixture), compiler)
        analyzeAll()
    }

    @AfterAll
    fun close() {
        if (::loaded.isInitialized) loaded.close()
    }

    // The other tests see the program analysed twice, as they would once the analysis is idempotent.
    @Test
    fun `analysing again lays every class struct as before`() {
        val before = classLayouts()
        analyzeAll()
        classLayouts() mustBe before
        program.dataTypeManager.allDataTypes.asSequence()
            .map { it.name }
            .filter { ".conflict" in it || it.endsWith("_data_1") }
            .toList() mustBe emptyList()
    }

    /** [cls]'s struct, a field per line: its offset, then its name and its type's. */
    protected fun Program.layout(cls: String) =
        (dataTypeManager.getDataType("/ClassDataTypes/$cls/$cls") as Structure).layout()

    private fun Structure.layout() = definedComponents.map { it.offset to "${it.fieldName}: ${it.dataType.name}" }

    private fun classLayouts() = program.dataTypeManager.allStructures.asSequence()
        .filter { it.categoryPath.path.startsWith("/ClassDataTypes/") }
        .associate { it.pathName to it.layout() }

    private fun analyzeAll() {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(TaskMonitor.DUMMY)
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
        }
    }
}
