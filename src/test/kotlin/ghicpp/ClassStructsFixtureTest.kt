package ghicpp

import ghicpp.entrypoints.ItaniumClassAnalyzer
import ghicpp.entrypoints.MsvcClassAnalyzer
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.LoadedProgram
import ghistabs.integration.FeatureFixtureTest
import ghistabs.loadProgram
import ghistabs.runTransaction
import ghistabs.set
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.io.File

/**
 * A stripped [fixture] under `features/` through the whole analysis, once for all its tests: the class pass
 * lays each class struct off the RTTI and the constructors, under [vfptrModel] for every class analyzer.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class ClassStructsFixtureTest(
    private val fixture: String,
    private val compiler: String,
    private val vfptrModel: VfptrModel = VfptrModel.OPTION.default,
) : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    protected val program: Program get() = loaded.program

    @BeforeAll
    fun analyze() {
        loaded = loadProgram(File(FeatureFixtureTest.FEATURES, fixture), compiler)
        program.runTransaction("vfptr model") {
            for (analyzer in listOf(ItaniumClassAnalyzer.NAME, MsvcClassAnalyzer.NAME)) {
                program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(analyzer)[VfptrModel.OPTION] = vfptrModel
            }
        }
        analyzeAll()
    }

    @AfterAll
    fun close() {
        if (::loaded.isInitialized) loaded.close()
    }

    // The other tests see the program analysed twice, as they would once the analysis is idempotent.
    @Test
    fun `analysing again lays every class struct as before, and adds no type but pointers`() {
        val layouts = classLayouts()
        val types = typePaths()
        analyzeAll()
        classLayouts() mustBe layouts
        typePaths() mustBe types
    }

    /** [cls]'s struct, a field per line: its offset, then its name and its type's. */
    protected fun Program.layout(cls: String) =
        (dataTypeManager.getDataType("/ClassDataTypes/$cls/$cls") as Structure).layout()

    private fun Structure.layout() = definedComponents.map { it.offset to "${it.fieldName}: ${it.dataType.name}" }

    private fun classLayouts() = program.dataTypeManager.allStructures.asSequence()
        .filter { it.categoryPath.path.startsWith("/ClassDataTypes/") }
        .associate { it.pathName to it.layout() }

    // A pointer to a type is made on use, which a second analysis may find more of.
    private fun typePaths() = program.dataTypeManager.allDataTypes.asSequence()
        .filterNot { it is Pointer }
        .map { it.pathName }
        .toSortedSet()

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
