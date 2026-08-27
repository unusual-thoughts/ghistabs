package ghistabs.probe

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions.Companion.LOG_LEVEL
import ghistabs.ImportOptions.Companion.SHORTEN_TYPEDEFS
import ghistabs.diagnose.Level
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.Harvester
import ghistabs.parse.StabReader
import ghistabs.render.Renderer
import ghistabs.render.Renderer.Mode
import ghistabs.runTransaction
import ghistabs.set
import ghistabs.test.defaultContext
import ghistabs.test.disableAnalyzersFromProperty
import ghistabs.test.disableWindowsResourceAnalyzer
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * Reconstruct a source-code skeleton per file mentioned by the binary's
 * stabs N_SOL / N_SLINE / N_FUN records. The output is structured so
 * each source line number lands on the same line in the skeleton —
 * blank lines pad gaps so a side-by-side view against the original
 * source aligns perfectly. Per line, we emit:
 *
 *  - function declaration + `{` when the function starts on that line
 *    (from N_FUN's desc field);
 *  - one `// 0xADDR: <code-unit>` annotation per N_SLINE entry on the
 *    line (the address is now absolute — added to the function's start
 *    in the harvester — and we attach Ghidra's code-unit description so
 *    the comment shows the actual instruction / data the line maps to);
 *  - `}` on the line immediately after the last N_SLINE entry that
 *    falls inside the function's `[addr, addr+sizeBytes)` range, unless
 *    that would collide with the next function's start (in which case
 *    the close moves up onto the last-statement line).
 *
 * Probe semantics: writes every [Mode] to `build/test-output/{skeletons,decomps,decomps_elide_sjlj}/
 * <fixture>/` (previous run rotated to `<dir>.old`) and only asserts that something was produced.
 * A generator — tagged `probe`, excluded from the default `integrationTest`; run via `probeDump`.
 */
@Tag("probe")
class SourceSkeletonProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @MethodSource("ghistabs.integration.Fixtures#all")
    fun writeRenderings(binaryName: String) = runPipeline(binaryName)

    private val Mode.outDirName get() = when (this) {
        Mode.SKELETON -> "skeletons"
        Mode.DECOMPILE -> "decomps"
        Mode.ELIDE_SJLJ -> "decomps_elide_sjlj"
    }

    // Load + auto-analyse + harvest once, then render every mode off that one harvest: the analysis
    // is ~95% of the runtime and only the Renderer differs per mode.
    private fun runPipeline(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler("gcc")
            .log(log).monitor(monitor).load().use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val ctx = program.defaultContext()
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                // Reconstruct with typedef-shortened names (string, vector<std::string>) so the
                // skeleton and decomp read like source rather than full template spellings.
                program.runTransaction("enable-typedef-shorten") {
                    program.getOptions(Program.ANALYSIS_PROPERTIES)
                        .getOptions("Stabs Importer")
                        .apply {
                            this[SHORTEN_TYPEDEFS] = true
                            this[LOG_LEVEL] = Level.DEBUG
                        }
                }
                program.disableWindowsResourceAnalyzer()
                // -PdisableAnalyzers=<substring> — render the same fixture twice, once without an
                // analyzer, and diff `<dir>.old` against `<dir>` to see exactly what it changes.
                program.disableAnalyzersFromProperty().forEach { println("Pipeline[$binaryName]: disabled $it") }
                mgr.reAnalyzeAll(null)
                program.runTransaction("skeleton-autoanalyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }
                val reader = StabReader.fromProgram(program)!!.readAll()
                val harvest = Harvester(ctx).harvest(reader.records)

                val index = HarvestIndex(harvest)
                val written = Mode.entries.sumOf { mode ->
                    val outDir = File("build/test-output/${mode.outDirName}/${fixture.nameWithoutExtension}")
                    if (outDir.exists()) {
                        val oldDir = File("${outDir.path}.old")
                        oldDir.deleteRecursively()
                        outDir.renameTo(oldDir)
                    }
                    Renderer(index, program, mode, ctx.resolver, sink = ctx).use { renderer ->
                        renderer.renderAll(outDir).also {
                            println(
                                "Pipeline[$binaryName, ${mode.outDirName}]: " +
                                    "${renderer.sources.size} sources, $it files → $outDir",
                            )
                        }
                    }
                }
                assumeTrue(written > 0, "no output (no N_SOL/N_SLINE in this binary?)")
            }
    }
}
