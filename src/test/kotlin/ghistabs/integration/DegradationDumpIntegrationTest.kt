package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.StabsOptions
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.importer.ImportContext
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * One-shot dump of every materialization degradation produced by the importer
 * with `logDegradations = true`. Writes per-fixture output to
 * `build/test-output/degradations/<fixture>.txt` grouped by category.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DegradationDumpIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(
        strings = [
            "bouniafbouniaf.exe", "xmltest", "bouniaf.exe", "box2d", "box2d_tests", "unbouniaf.exe", "bouniaf.exe",
        ],
    )
    fun dumpDegradations(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler(if (fixture.extension.lowercase() == "exe") "gcc" else null)
            .log(log)
            .monitor(monitor)
            .load()
            .use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val ctx = ImportContext(
                    program,
                    monitor,
                    StabsOptions(),
                    CapturingSink(),
                    StabsDiagnostics(),
                )
                program.runTransaction("stabs-degradation-dump") {
                    ctx.import()
                }

                val events = ctx.diagnostics.snapshotDegradations()
                val byCategory = events.groupBy { it.category }
                    .toList()
                    .sortedByDescending { it.second.size }

                val out = File("build/test-output/degradations/${fixture.nameWithoutExtension}.txt")
                out.parentFile.mkdirs()
                out.bufferedWriter().use { w ->
                    w.write("fixture: $binaryName\n")
                    w.write("total degradations: ${events.size}\n\n")
                    w.write("counts by category:\n")
                    for ((cat, list) in byCategory) w.write("  $cat = ${list.size}\n")
                    w.write("\n")
                    for ((cat, list) in byCategory) {
                        w.write("=== $cat (${list.size}) ===\n")
                        for (e in list) w.write("  ${e.detail}\n")
                        w.write("\n")
                    }
                }
                println("[$binaryName] wrote ${events.size} events to ${out.absolutePath}")
                for ((cat, list) in byCategory) println("  $cat = ${list.size}")

                program.release(this)
            }
    }
}
