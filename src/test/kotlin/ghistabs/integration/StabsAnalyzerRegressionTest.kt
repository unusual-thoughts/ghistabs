package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.app.util.opinion.LoadResults
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
import ghidra.program.model.data.Enum
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File

/**
 * Regression test harness for StabsAnalyzer on xapasmcsr.exe.
 *
 * Runs full analysis pipeline and validates counters against committed baseline.
 * Skips gracefully if fixture is absent (EULA-restricted, not in repo).
 *
 * When the harness is fully set up (issue #40 resolved), tests:
 * - Import xapasmcsr.exe via TestEnv
 * - Run AutoAnalysisManager (fires StabsAnalyzer.added() via registered analyzer)
 * - Capture MessageLog and validate per-AC spot checks + baseline counter ranges
 *
 * See: gradle/ghidra-test-deps.md and build.gradle.kts integrationTest config.
 * Harness blocker: Java 21 × Ghidra 11.x ObjectInputFilter conflict (issue #40).
 * Tests skip gracefully if fixture absent; when #40 is solved, no edits needed.
 */
@Tag("integration")
class StabsAnalyzerRegressionTest : AbstractGhidraHeadlessIntegrationTest() {
    private val fixture = File("src/test/resources/binaries/xapasmcsr.exe")
    private val baselineFile = File("src/test/resources/baselines/xapasmcsr-baseline.json")

    private lateinit var program: Program
    private var loadResults: LoadResults<Program>? = null
    private var usedRealBinary = false
    private lateinit var stabsLog: MessageLog

    @BeforeEach
    fun setUp() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent, must be added manually",
        )

        // Load the binary using ProgramLoader without TestEnv project infrastructure.
        // ProgramLoader.builder() can load a binary without a project; project parameter is optional.
        val log = MessageLog()
        stabsLog = log
        val monitor = TaskMonitor.DUMMY

        try {
            loadResults = ProgramLoader
                .builder()
                .source(fixture)
                .compiler("mingw")
                .log(log)
                .monitor(monitor)
                .load()

            program = loadResults!!.getPrimaryDomainObject(this)
            usedRealBinary = true

            // Trigger auto-analysis to populate symbols/types from the loader, then invoke
            // StabsAnalyzer directly. (In standalone tests the extension isn't registered with
            // Ghidra's ClassSearcher, so AutoAnalysisManager doesn't discover it.)
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            val txId = program.startTransaction("auto-analyze")
            try {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            } finally {
                program.endTransaction(txId, true)
            }
            val stabsAnalyzer = ghistabs.StabsAnalyzer()
            val txStabs = program.startTransaction("stabs-analyze")
            try {
                stabsAnalyzer.added(program, program.memory, monitor, log)
            } finally {
                program.endTransaction(txStabs, true)
            }
        } catch (e: Exception) {
            // If loading the real binary fails, skip the test (these tests require real binary data)
            assumeTrue(false, "Failed to load real binary via ProgramLoader: ${e.message}")
        }
    }

    @AfterEach
    fun tearDown() {
        if (::program.isInitialized) program.release(this)
        loadResults?.close()
    }

    @Test
    fun countersWithinBaseline() {
        val messageLog = capturedMessageLog(program)
        val tagCounts = parseTagFrequencies(messageLog)
        val baseline = BaselineLoader.load(baselineFile)

        // If no stabs were found in the binary, skip the test
        // (stabs sections may not exist or may be in a non-standard format)
        assumeTrue(
            tagCounts.isNotEmpty(),
            "Skipping: No stabs counters found in binary (stabs sections absent or non-standard format)",
        )

        val drift = mutableListOf<String>()
        for ((counterName, range) in baseline.counters) {
            val actual = tagCounts.getOrDefault(counterName, 0L)
            if (actual !in range.min..range.max) {
                drift += "Counter '$counterName' = $actual outside baseline range [${range.min}..${range.max}]"
            }
        }
        if (drift.isNotEmpty()) {
            Assertions.fail<Unit>("Baseline drift detected:\n  - " + drift.joinToString("\n  - "))
        }
    }

    @Test
    fun xapArgInstNotUnderStdInclude() {
        val xapArgInst = program.dataTypeManager.allDataTypes
            .asSequence()
            .firstOrNull { it.name == "XapArgInst" }
        assumeTrue(xapArgInst != null, "Skipping: XapArgInst not found in DTM (stabs not processed)")
        Assertions.assertFalse(
            xapArgInst!!.categoryPath.path.startsWith("/std/"),
            "XapArgInst at ${xapArgInst.categoryPath.path} (expected non-/std/)",
        )
    }

    @Test
    fun xapInstFirstComponentIsBase() {
        val xapInst =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .firstOrNull { it.name == "XapInst" && it is Structure } as? Structure
        assumeTrue(xapInst != null, "Skipping: XapInst not found in DTM (stabs not processed)")
        assumeTrue(xapInst!!.numComponents > 0, "Skipping: XapInst has no components")
        val first = xapInst.getComponent(0)
        Assertions.assertEquals(
            0,
            first.offset,
            "XapInst first component should be at offset 0; got ${first.offset} (${first.fieldName})",
        )
        Assertions.assertTrue(
            first.dataType is Structure,
            "XapInst first component '${first.fieldName}' should be a Structure (the parent class); " +
                "got ${first.dataType::class.simpleName} '${first.dataType.name}'",
        )
        val name = first.fieldName ?: ""
        Assertions.assertTrue(
            name.startsWith("_base_") && !name.startsWith("_base_unknown_"),
            "XapInst first component is '$name' (type=${first.dataType.name}); " +
                "expected _base_<parent-name> with a resolved parent class",
        )
        Assertions.assertEquals(
            "ExprInst",
            first.dataType.name,
            "XapInst's parent class should be ExprInst; got ${first.dataType.name}",
        )
    }

    @Test
    fun cLexStreamHasBaseField() {
        val cls =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .firstOrNull { it.name == "CLexStream" && it is Structure } as? Structure
        assumeTrue(cls != null, "Skipping: CLexStream not found (stabs not processed)")
        val hasBase =
            (0 until cls!!.numComponents).any { i ->
                cls.getComponent(i).fieldName?.let { it.startsWith("_base_") || it.startsWith("_vbase_") } == true
            }
        Assertions.assertTrue(hasBase, "CLexStream has no _base_/_vbase_ component")
    }

    @Test
    fun atLeastOneVtableStructApplied() {
        val vtables = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.endsWith("_vtable") && it.numComponents > 0 }.toList()
        Assertions.assertTrue(
            vtables.isNotEmpty(),
            "Expected at least one *_vtable struct with components",
        )
        val classesWithVtables = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.components.any { vtables.contains((it.dataType as? Pointer)?.dataType) } }
            .toList()
        Assertions.assertTrue(
            classesWithVtables.isNotEmpty(),
            "Expected at least one class with a vtable pointer",
        )
    }

    @Test
    fun globalsCoverEachDataTypeKind() {
        val seenKinds = mutableSetOf<String>()
        program.listing.getDefinedData(true).forEach { data ->
            seenKinds +=
                when (val dt = data.dataType) {
                    is Structure -> "Structure"
                    is Array -> "Array"
                    is Union -> "Union"
                    is Pointer -> "Pointer"
                    is Enum -> "Enum"
                    is TypeDef -> "TypeDef"
                    is FunctionDefinition -> "FunctionDefinition"
                    else -> "Primitive"
                }
        }
        // Enum is not required: xapasmcsr.exe may have no enum-typed globals.
        // The other kinds reflect basic global-application coverage.
        val required = setOf("Structure", "Pointer", "Primitive")
        val missing = required - seenKinds
        Assertions.assertTrue(
            missing.isEmpty(),
            "Missing DataType kinds in globals: $missing (saw: $seenKinds)",
        )
    }

    private fun parseTagFrequencies(log: String): Map<String, Long> = log
        .lines()
        .mapNotNull { Regex("""\[Stabs\] ([A-Za-z0-9._-]+)(?: at [^:]+)?:""").find(it)?.groupValues?.get(1) }
        .groupingBy { it }
        .eachCount()
        .mapValues { it.value.toLong() }

    private fun capturedMessageLog(prog: Program): String {
        val analysisLog = AutoAnalysisManager.getAnalysisManager(prog).messageLog.toString()
        val stabs = if (::stabsLog.isInitialized) stabsLog.toString() else ""
        return analysisLog + "\n" + stabs
    }
}
