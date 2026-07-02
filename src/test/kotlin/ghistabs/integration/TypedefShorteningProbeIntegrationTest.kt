package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.data.Composite
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.defaultContext
import ghistabs.materialize.TypedefShortener
import ghistabs.runTransaction
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * Runs the #7 typedef-shortening pass against a real fixture DTM after full autoanalyze
 * (which materialises the stabs types) and dumps every rename it computes to
 * `build/test-output/typedef-renames/<fixture>.txt`. Then applies them and asserts the
 * canonical std::string collapse actually landed, so the DTM plumbing — not just the pure
 * algorithm ([ghistabs.materialize.typedefShorteningRenames]) — is exercised.
 */
@Tag("integration")
class TypedefShorteningProbeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(strings = ["appquery.exe", "xapasmcsr.exe"])
    fun dumpRenames(binaryName: String) {
        val filter = System.getProperty("fixtureFilter").orEmpty()
        assumeTrue(filter.isEmpty() || filter == binaryName, "fixture filtered out by -Pfixture")
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler(if (fixture.extension.lowercase() == "exe") "gcc" else null)
            .log(MessageLog()).monitor(monitor).load().use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(null)
                program.runTransaction("probe-autoanalyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }

                val shortener = TypedefShortener(program.dataTypeManager, program.defaultContext().sink)
                val renames = shortener.renames().sortedByDescending { it.from.length - it.to.length }

                val outDir = File("build/test-output/typedef-renames").apply { mkdirs() }
                File(outDir, "${fixture.nameWithoutExtension}.txt").writeText(
                    renames.joinToString("\n") { "${it.from}\n  -> ${it.to}" },
                )
                println("Typedef-shorten[$binaryName]: ${renames.size} renames → $outDir")
                renames.take(8).forEach { println("  ${it.from}\n    -> ${it.to}") }

                assumeTrue(renames.isNotEmpty(), "no shortenable typedefs in this binary")
                // The std::string collapse is the canonical case; verify it applies on the real DTM
                // — including folding the pre-existing `string` typedef out of the way (name collision).
                assumeTrue(renames.any { it.to == "string" }, "no std::string typedef in this binary")
                val renamed = program.runTransaction("probe-apply") { shortener.apply() }
                assertTrue(renamed > 0, "apply renamed nothing")
                val stringStruct = program.dataTypeManager.allDataTypes.asSequence()
                    .any { it.name == "string" && it is Composite }
                assertEquals(true, stringStruct, "basic_string should now be a Composite named 'string'")
            }
    }
}
