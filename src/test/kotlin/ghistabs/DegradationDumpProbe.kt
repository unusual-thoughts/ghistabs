package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.importer.ImportContext
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * One-shot dump of every materialization degradation produced by the importer
 * with `logDegradations = true`. Writes per-fixture output to
 * `build/test-output/degradations/<fixture>.txt` grouped by category. A generator, not a
 * pass/fail test — tagged `probe`, excluded from the default `integrationTest`; run via `probeDump`.
 */
@Tag("probe")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DegradationDumpProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @MethodSource("ghistabs.IntegrationFixtures#all")
    fun dumpDegradations(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler("gcc")
            .log(log)
            .monitor(monitor)
            .load()
            .use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val ctx = ImportContext(
                    program,
                    monitor,
                    ImportOptions(),
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
                // Full untruncated run log (CapturingSink holds every level, unfiltered),
                // mirroring StabsImportRegressionTest so import diagnostics are inspectable per fixture.
                val logFile = File("build/test-output/logs/${fixture.nameWithoutExtension}.degradation.log")
                logFile.parentFile.mkdirs()
                logFile.writeText(ctx.terminal.dedupedOutput() + "\n--- MessageLog ---\n" + log.toString())

                println("[$binaryName] wrote ${events.size} events to ${out.absolutePath}")
                for ((cat, list) in byCategory) println("  $cat = ${list.size}")

                program.release(this)
            }
    }
}
