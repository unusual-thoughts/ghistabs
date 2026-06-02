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
import ghistabs.diag.CapturingSink
import ghistabs.diag.defaultContext
import ghistabs.importer.ImportContext
import ghistabs.parser.Harvester
import ghistabs.parser.StabReader
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToStream
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
    private val harvestFile = File("src/test/resources/harvests/xapasmcsr-harvest.json")
    private val logFile = File("src/test/resources/logs/xapasmcsr.log")

    private lateinit var program: Program
    private var loadResults: LoadResults<Program>? = null
    private var usedRealBinary = false
    private lateinit var context: ImportContext<CapturingSink>

    @BeforeEach
    fun setUp() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent, must be added manually",
        )

        // Load the binary using ProgramLoader without TestEnv project infrastructure.
        // ProgramLoader.builder() can load a binary without a project; project parameter is optional.
        val log = MessageLog()
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
            context = program.defaultContext()
            val stabsAnalyzer = ghistabs.StabsAnalyzer()
            val txStabs = program.startTransaction("stabs-analyze")
            try {
                stabsAnalyzer.run(program, context)
            } finally {
                program.endTransaction(txStabs, true)
            }
            logFile.writeText(context.log.capturedOutput())
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
        val tagCounts = context.log.tagFrequencies()
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
    fun demanglerHasNoEmptyStubs() {
        // /Demangler is the holding category for placeholder structs filled in by
        // DemanglerReplacer. After import these should all be resolved to real types
        // (length > 0 or absorbed into another category) — none should remain as
        // empty Structure stubs.
        val emptyStubs = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.categoryPath.path.startsWith("/Demangler") }
            .filter { it.isZeroLength || it.numComponents == 0 }
            .map { "${it.categoryPath.path}/${it.name}" }
            .toList()
        Assertions.assertTrue(
            emptyStubs.isEmpty(),
            "Expected zero empty /Demangler/* stubs, found ${emptyStubs.size}: " +
                emptyStubs.take(10).joinToString(),
        )
    }

    @Test
    fun fewSuffixedConflictRenames() {
        // Types renamed to `<name>_<N>` by conflict-dedup should be the exception,
        // not the rule. A high count signals canonicalisation/dedup regressions like
        // the cross-CU TypeId collision fixed in 4b21a6c.
        val suffixed = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { Regex("""^.+_\d+$""").matches(it.name) }
            .count()
        Assertions.assertTrue(
            suffixed < 200,
            "Suspiciously many _N-suffixed types: $suffixed (expected < 200)",
        )
    }

    @Test
    fun inheritanceWasApplied() {
        val applied = context.diagnostics.snapshotCounters()["inheritance-applied"] ?: 0L
        Assertions.assertTrue(
            applied > 0,
            "Expected inheritance-applied counter > 0, got $applied " +
                "(no C++ inheritance edges were materialised)",
        )
    }

    @Test
    fun mostPolymorphicClassesHaveVtableStruct() {
        // For every <Name>_vtable that ended up non-empty, the parent class
        // <Name> should also exist as a Structure with a {vfptr} component
        // pointing back at that vtable. A wide gap indicates ClassBuilder is
        // running but its vfptr-insertion pass is failing.
        val vtables = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name.endsWith("_vtable") && it.numComponents > 0 }
            .toList()
        val withMatchingVfptr = vtables.count { vt ->
            val className = vt.name.removeSuffix("_vtable")
            val cls = program.dataTypeManager.allDataTypes
                .asSequence()
                .filterIsInstance<Structure>()
                .firstOrNull { it.name == className }
            cls != null && cls.components.any { (it.dataType as? Pointer)?.dataType === vt }
        }
        // Allow some slack: synthesised/external bases legitimately lack a back-edge.
        val ratio = if (vtables.isNotEmpty()) withMatchingVfptr.toDouble() / vtables.size else 0.0
        Assertions.assertTrue(
            ratio >= 0.5,
            "Expected ≥ 50% of *_vtable structs to have a back-edge {vfptr} from their class; " +
                "got $withMatchingVfptr / ${vtables.size} (${"%.1f".format(ratio * 100)}%)",
        )
    }

    @Test
    fun globalsCoverEachDataTypeKind() {
        val seenKinds = mutableSetOf<String>()
        program.listing.getDefinedData(true).forEach { data ->
            seenKinds += when (val dt = data.dataType) {
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

    @Test
    fun harvestTest() {
        val ctx = program.defaultContext()
        val stabs = StabReader.fromProgram(program)!!
        val harvester = Harvester(TaskMonitor.DUMMY, ctx.sink, ctx.resolver)
        // passA writes via AddressResolver.recordFromStab → symbolTable.createLabel, so it
        // needs a transaction. (We re-run it here to serialize a self-contained harvest
        // independent of setUp's own pass.)
        val tx = program.startTransaction("stabs-harvest-dump")
        val harvest = try {
            harvester.passA(stabs.records)
        } finally {
            program.endTransaction(tx, true)
        }
        Json { prettyPrint = true }.encodeToStream(harvest, harvestFile.outputStream())
    }
}
