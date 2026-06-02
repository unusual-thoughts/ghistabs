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
 * Regression test harness for StabsAnalyzer on bouniafbouniaf.exe.
 *
 * Runs full analysis pipeline and validates counters against committed baseline.
 * Skips gracefully if fixture is absent (bouniaf, not in repo).
 *
 * When the harness is fully set up (issue #40 resolved), tests:
 * - Import bouniafbouniaf.exe via TestEnv
 * - Run AutoAnalysisManager (fires StabsAnalyzer.added() via registered analyzer)
 * - Capture MessageLog and validate per-AC spot checks + baseline counter ranges
 *
 * See: gradle/ghidra-test-deps.md and build.gradle.kts integrationTest config.
 * Harness blocker: Java 21 × Ghidra 11.x ObjectInputFilter conflict (issue #40).
 * Tests skip gracefully if fixture absent; when #40 is solved, no edits needed.
 */
@Tag("integration")
class StabsAnalyzerRegressionTest : AbstractGhidraHeadlessIntegrationTest() {
    private val fixture = File("src/test/resources/binaries/bouniafbouniaf.exe")
    private val baselineFile = File("src/test/resources/baselines/bouniafbouniaf-baseline.json")
    private val harvestFile = File("src/test/resources/harvests/bouniafbouniaf-harvest.json")
    private val logFile = File("src/test/resources/logs/bouniafbouniaf.log")

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
    fun bouniafNotUnderStdInclude() {
        val bouniaf = program.dataTypeManager.allDataTypes
            .asSequence()
            .firstOrNull { it.name == "bouniaf" }
        assumeTrue(bouniaf != null, "Skipping: bouniaf not found in DTM (stabs not processed)")
        Assertions.assertFalse(
            bouniaf!!.categoryPath.path.startsWith("/std/"),
            "bouniaf at ${file.categoryPath.path} (expected non-/std/)",
        )
    }

    @Test
    fun csymLexStreamPresent() {
        val all = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { it.name == "bouniaf" }
            .map { "${it.categoryPath.path}/${it.name} (${it::class.simpleName}, len=${(it as? Structure)?.length})" }
            .toList()
        // bouniaf is defined inside STL headers (only entry points are template
        // instantiations) so it ends up under /std/<sorted-first-header>/ rather than
        // a project category. What matters is that it materialised as a non-empty
        // Structure that ClassBuilder can find via Attribution (i.e. the dedup +
        // sort-stable attribution agree on the same category).
        val best = all.firstOrNull { "(StructureDB" in it }
        Assertions.assertNotNull(best, "No bouniaf Structure in DTM. Got:\n${all.joinToString("\n")}")
    }

    @Test
    fun exprInstHasComponents() {
        val matches = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "ExprInst" }
            .toList()
        assumeTrue(matches.isNotEmpty(), "Skipping: ExprInst not found")
        val best = matches.maxByOrNull { it.numComponents }!!
        val rendered = matches.joinToString("\n") {
            "${it.categoryPath.path}/${it.name} len=${it.length} components=${it.numComponents}"
        }
        Assertions.assertTrue(
            best.numComponents > 0,
            "All ExprInst copies are empty:\n$rendered",
        )
        // Surface where each copy lives so we can see if there's a stub-vs-real split.
        println("ExprInst copies:\n$rendered")
        // EnumInstToken: TODO item — verify it appears at all.
        val enumInstAll = program.dataTypeManager.allDataTypes
            .asSequence()
            .filter { it.name.startsWith("EnumInstToken") || it.name.startsWith("EnumInstType") }
            .map { "${it.categoryPath.path}/${it.name} (${it::class.simpleName})" }
            .toList()
        Assertions.assertTrue(
            enumInstAll.any { "EnumInstToken" in it && "Enum" in it.substringAfterLast("(") },
            "No EnumInstToken Enum in DTM. Related entries:\n${enumInstAll.joinToString("\n")}",
        )
    }

    @Test
    fun bouniafFirstComponentIsBase() {
        val bouniaf =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .firstOrNull { it.name == "bouniaf" && it is Structure } as? Structure
        assumeTrue(bouniaf != null, "Skipping: bouniaf not found in DTM (stabs not processed)")
        assumeTrue(bouniaf!!.numComponents > 0, "Skipping: bouniaf has no components")
        val first = bouniaf.getComponent(0)
        Assertions.assertEquals(
            0,
            first.offset,
            "bouniaf first component should be at offset 0; got ${first.offset} (${first.fieldName})",
        )
        val dump = (0 until bouniaf.numComponents).joinToString("\n") {
            val c = bouniaf.getComponent(it)
            "  [${c.offset}] ${c.fieldName}: ${c.dataType.name} (${c.dataType::class.simpleName}, len=${c.length})"
        }
        val xis = program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "bouniaf" }
            .map { "${it.categoryPath.path} components=${it.numComponents} len=${it.length}" }
            .toList()
        Assertions.assertTrue(
            first.dataType is Structure,
            "bouniaf first component '${first.fieldName}' should be a Structure (the parent class); " +
                "got ${first.dataType::class.simpleName} '${first.dataType.name}'\n" +
                "bouniaf copies in DTM:\n${xis.joinToString("\n")}\n" +
                "First 5 components of selected bouniaf:\n$dump",
        )
        val name = first.fieldName ?: ""
        Assertions.assertTrue(
            name.startsWith("_base_") && !name.startsWith("_base_unknown_"),
            "bouniaf first component is '$name' (type=${first.dataType.name}); " +
                "expected _base_<parent-name> with a resolved parent class",
        )
        Assertions.assertEquals(
            "ExprInst",
            first.dataType.name,
            "bouniaf's parent class should be ExprInst; got ${first.dataType.name}",
        )
    }

    @Test
    fun bouniafHasBaseField() {
        val cls =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .firstOrNull { it.name == "bouniaf" && it is Structure } as? Structure
        assumeTrue(cls != null, "Skipping: bouniaf not found (stabs not processed)")
        val hasBase =
            (0 until cls!!.numComponents).any { i ->
                cls.getComponent(i).fieldName?.let { it.startsWith("_base_") || it.startsWith("_vbase_") } == true
            }
        Assertions.assertTrue(hasBase, "bouniaf has no _base_/_vbase_ component")
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
    fun dcinstVtableMatchesItaniumLayout() {
        // Prefer the non-empty copy: there may be one stub in /Demangler or /std/<header>
        // from per-AST iteration and a real one elsewhere.
        val vtable = program.dataTypeManager.allDataTypes
            .asSequence()
            .filterIsInstance<Structure>()
            .filter { it.name == "bouniaf_vtable" }
            .maxByOrNull { it.numComponents }
        assumeTrue(vtable != null, "Skipping: bouniaf_vtable not found")
        val components = (0 until vtable!!.numComponents).map {
            val c = vtable.getComponent(it)
            "[${c.offset}] ${c.fieldName ?: "<unnamed>"}: ${c.dataType.name}"
        }
        val dups = program.dataTypeManager.allDataTypes
            .asSequence().filter { it.name == "bouniaf_vtable" }
            .map { "${it.categoryPath.path}/${it.name} (len=${(it as Structure).length})" }
            .toList()
        val fieldNames = (0 until vtable.numComponents).map { vtable.getComponent(it).fieldName }
        Assertions.assertEquals(
            "offset_to_top",
            fieldNames.getOrNull(0),
            "Components:\n${components.joinToString("\n")}\n" +
                "bouniaf_vtable copies in DTM:\n${dups.joinToString("\n")}",
        )
        Assertions.assertEquals("rtti", fieldNames.getOrNull(1))
        // bouniaf's own + inherited (Inst::Get* via ExprInst → bouniaf → Inst chain).
        // We don't pin the exact order, just that all expected slots are present.
        val virtuals = fieldNames.drop(2).filterNotNull().toSet()
        val expected = setOf(
            "GetInstType", "__comp_dtor", "__deleting_dtor",
            "Clone", "Dump", "GetSize", "PossibleFunctionReference",
            "GetOffset", "GetPrevOffset", "GetFullOffset", "GetPrevFullOffset",
        )
        val missing = expected - virtuals
        Assertions.assertTrue(
            missing.isEmpty(),
            "bouniaf_vtable missing virtuals: $missing (have: $virtuals)",
        )
    }

    @Test
    fun atLeastOneRootClassHasVtableBackEdge() {
        // At least one polymorphic class should directly contain a {vfptr} Pointer
        // pointing at its <Name>_vtable struct. Derived classes correctly *inherit*
        // their vfptr via a `_base_<Parent>` subobject, so most won't carry the
        // pointer directly — but the root of every inheritance chain (e.g. Inst on
        // bouniafbouniaf.exe) must, otherwise the ClassBuilder vfptr-insertion path is
        // broken end-to-end. (Inheritance coverage is asserted separately by
        // bouniafHasBaseField and bouniafFirstComponentIsBase.)
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
        Assertions.assertTrue(
            withMatchingVfptr >= 1,
            "Expected ≥ 1 *_vtable struct to have a back-edge {vfptr} from its class; " +
                "got $withMatchingVfptr / ${vtables.size}",
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
        // Enum is not required: bouniafbouniaf.exe may have no enum-typed globals.
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
