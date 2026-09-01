package ghistabs.probe

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions.Companion.LOG_LEVEL
import ghistabs.ImportOptions.Companion.SHORTEN_TYPEDEFS
import ghistabs.ImportOptions.Companion.SOURCE_ROOTS
import ghistabs.diagnose.Level
import ghistabs.harvest.Harvester
import ghistabs.parse.StabReader
import ghistabs.render.Renderer
import ghistabs.render.Renderer.Mode
import ghistabs.render.Scorecard
import ghistabs.runTransaction
import ghistabs.set
import ghistabs.test.defaultContext
import ghistabs.test.disableWindowsResourceAnalyzer
import ghistabs.test.hintsOf
import ghistabs.withProgram
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * Grade what the render attributes against the sources it was built from, per §44: how many inlined
 * stretches the real source can name, and how many declarations sit where the file that declares
 * them says they do. Writes `build/test-output/attribution/<fixture>.txt` — the table and the items
 * behind it — and leaves the decompilation it graded beside it.
 *
 * The root comes from `-PsourceRoot=<dir>[;<dir>]` or `GHISTABS_SOURCE_ROOT`, so a laptop with a gcc
 * checkout and CI without one need no code change between them: with no root there is nothing to
 * grade against and the probe skips.
 *
 * DECOMPILE mode, because the inline half only exists there — a skeleton has no regions, so nothing
 * asks the source what a stretch is part of.
 */
@Tag("probe")
class AttributionProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @MethodSource("ghistabs.integration.Fixtures#all")
    fun grade(binaryName: String) {
        // The environment too, and not only through gradle's `-PsourceRoot`, so the probe runs from an IDE.
        val roots = listOfNotNull(System.getProperty("sourceRoot"), System.getenv("GHISTABS_SOURCE_ROOT"))
            .firstOrNull { it.isNotBlank() }.orEmpty()
            .split(';').map(String::trim).filter { it.isNotEmpty() }
        assumeTrue(roots.isNotEmpty(), "no source root (-PsourceRoot=<dir> or GHISTABS_SOURCE_ROOT)")
        roots.forEach { assumeTrue(File(it).isDirectory, "source root $it is not a directory") }
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        withProgram(fixture, log = log, monitor = monitor) { program ->
            val ctx = program.defaultContext()
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            // Set before analysis: the analyzer's import is what registers the directory transforms
            // this render then reads back through.
            program.runTransaction("configure-source-roots") {
                program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions("Stabs Importer").apply {
                    this[SOURCE_ROOTS] = roots
                    this[SHORTEN_TYPEDEFS] = true
                    this[LOG_LEVEL] = Level.DEBUG
                }
            }
            program.disableWindowsResourceAnalyzer()
            mgr.reAnalyzeAll(null)
            program.runTransaction("attribution-autoanalyze") {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            }
            val reader = StabReader.fromProgram(program)!!.readAll()
            val harvest = program.runTransaction("attribution-harvest") { Harvester(ctx).harvest(reader.records) }
            // Through the run's sink, so the scorecard's counters land where this can read them back.
            val hints = hintsOf(harvest, sink = ctx)

            val out = File("build/test-output/attribution")
            out.mkdirs()
            val name = fixture.nameWithoutExtension
            Renderer(
                Mode.DECOMPILE,
                hints,
                program,
                ctx.resolver,
                sink = ctx,
            ).use { renderer ->
                assumeTrue(renderer.renderAll(out.resolve(name)) > 0, "nothing rendered")
                // After the render, never during one: the inline half is graded on the questions the
                // render itself put to the source, and grading is this probe's job, not a render's.
                val scorecard = Scorecard(renderer).apply { tally() }
                val counters = ctx.diagnostics.snapshotCounters()
                    .filterKeys { it.startsWith("source-") }
                    .map { (k, v) -> "  %-28s %5d".format(k, v) }
                out.resolve("$name.txt").writeText(
                    scorecard.report("$name against ${roots.joinToString()}") +
                        // What the root itself did — a wrong tree shows up here as mismatches and
                        // unregistered directories before it shows up as a worse score.
                        "\nroot diagnostics\n" + counters.sorted().joinToString("\n") + "\n",
                )
                println("Attribution[$binaryName]: ${out.resolve("$name.txt")}")
            }
        }
    }
}
