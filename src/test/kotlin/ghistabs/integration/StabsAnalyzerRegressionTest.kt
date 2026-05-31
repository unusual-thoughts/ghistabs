package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.data.Array
import ghidra.program.model.data.Enum
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.TypeDef
import ghidra.program.model.data.Union
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.test.TestEnv
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
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

    private var env: TestEnv? = null
    private lateinit var program: Program

    @BeforeEach
    fun setUp() {
        assumeTrue(
            fixture.exists(),
            "Skipping: ${fixture.path} absent (bouniaf, must be added manually)",
        )

        try {
            env = TestEnv()
            // Call env.openProgram(fixture) directly
            @Suppress("UNCHECKED_CAST")
            val method = env!!::class.java.getMethod("openProgram", File::class.java)
            program = (method.invoke(env!!, fixture) as Program)
        } catch (e: IllegalStateException) {
            // If JVM initialization fails due to issue #40 (ObjectInputFilter conflict),
            // skip gracefully
            if (e.message?.contains("filter factory") == true) {
                assumeTrue(false, "TestEnv fixture loading failed (issue #40): ${e.message}")
            } else {
                throw e
            }
        }
    }

    @AfterEach
    fun tearDown() {
        env?.dispose()
    }

    @Test
    fun countersWithinBaseline() {
        val messageLog = capturedMessageLog(program)
        val tagCounts = parseTagFrequencies(messageLog)
        val baseline = BaselineLoader.load(baselineFile)

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
        val bouniaf =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .firstOrNull { it.name == "bouniaf" }
        Assertions.assertNotNull(bouniaf, "bouniaf not found in DTM at all")
        Assertions.assertFalse(
            bouniaf!!.categoryPath.path.startsWith("/std/"),
            "bouniaf at ${file.categoryPath.path} (expected non-/std/)",
        )
    }

    @Test
    fun bouniafHasBaseField() {
        val cls =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .firstOrNull { it.name == "bouniaf" && it is Structure } as? Structure
        Assertions.assertNotNull(cls, "bouniaf not found")
        val hasBase =
            (0 until cls!!.numComponents).any { i ->
                cls.getComponent(i).fieldName?.let { it.startsWith("_base_") || it.startsWith("_vbase_") } == true
            }
        Assertions.assertTrue(hasBase, "bouniaf has no _base_/_vbase_ component")
    }

    @Test
    fun atLeastOneVtableStructApplied() {
        val any =
            program.dataTypeManager.allDataTypes
                .asSequence()
                .filterIsInstance<Structure>()
                .any { it.name.endsWith("_vtable") && it.numComponents > 0 }
        Assertions.assertTrue(any, "No populated *_vtable struct found")
    }

    @Test
    fun bss0x46702cNamedOrDocumented() {
        val addr = program.addressFactory.defaultAddressSpace.getAddress(0x46702cL)
        val named = program.symbolTable.getPrimarySymbol(addr) != null
        val messageLog = capturedMessageLog(program)
        val documented = messageLog.contains("stabs-no-coverage") && messageLog.contains("0x46702c")
        Assertions.assertTrue(named || documented, "0x46702c neither named nor documented as stabs-no-coverage")
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
        val required = setOf("Structure", "Pointer", "Enum", "Primitive")
        val missing = required - seenKinds
        Assertions.assertTrue(missing.isEmpty(), "Missing DataType kinds in globals: $missing (seen: $seenKinds)")
    }

    private fun parseTagFrequencies(log: String): Map<String, Long> =
        log
            .lines()
            .mapNotNull { Regex("""^\[Stabs\] ([a-z-]+):""").find(it)?.groupValues?.get(1) }
            .groupingBy { it }
            .eachCount()
            .mapValues { it.value.toLong() }

    private fun capturedMessageLog(prog: Program): String =
        AutoAnalysisManager
            .getAnalysisManager(prog)
            .messageLog
            .toString()
}
