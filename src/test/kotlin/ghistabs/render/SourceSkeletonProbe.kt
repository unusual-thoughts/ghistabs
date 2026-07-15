package ghistabs.render

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.diagnose.Level
import ghistabs.diagnose.defaultContext
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeResolver
import ghistabs.parse.StabReader
import ghistabs.render.Mode
import ghistabs.render.Renderer
import ghistabs.runTransaction
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
 * source aligns perfectly. Per line we emit:
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
 * Probe semantics: writes to `build/test-output/skeletons/<fixture>/` and only asserts that at
 * least one skeleton was produced. A generator — tagged `probe`, excluded from the default
 * `integrationTest`; run via `probeDump`.
 */
@Tag("probe")
class SourceSkeletonProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @MethodSource("ghistabs.IntegrationFixtures#all")
    fun writeSkeletons(binaryName: String) = runPipeline(binaryName, decompile = false)

    @ParameterizedTest
    @MethodSource("ghistabs.IntegrationFixtures#all")
    fun writeDecompilations(binaryName: String) = runPipeline(binaryName, decompile = true)

    private fun runPipeline(binaryName: String, decompile: Boolean) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")
        val outDirName = if (decompile) "decomps" else "skeletons"
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
                            setBoolean(StabsOptions.SHORTEN_TYPEDEFS, true)
                            setEnum(StabsOptions.LOG_LEVEL, Level.DEBUG)
                        }
                }
                mgr.reAnalyzeAll(null)
                program.runTransaction("skeleton-autoanalyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }
                val reader = StabReader.fromProgram(program)!!.readAll()
                val harvest = program.runTransaction("skeleton-harvest") {
                    Harvester(ctx).harvest(reader.records)
                }

                val outDir = File("build/test-output/$outDirName/${fixture.nameWithoutExtension}")
                if (outDir.exists()) {
                    val oldDir = File("${outDir.path}.old")
                    oldDir.deleteRecursively()
                    outDir.renameTo(oldDir)
                }
                val mode = if (decompile) Mode.ELIDE_SJLJ else Mode.SKELETON
                Renderer(TypeResolver(harvest), program, mode, ctx.resolver).use { renderer ->
                    val written = renderer.renderAll(outDir)
                    println(
                        "Pipeline[$binaryName, $outDirName]: ${renderer.sources.size} sources, $written files → $outDir",
                    )
                    assumeTrue(written > 0, "no output (no N_SOL/N_SLINE in this binary?)")
                }
            }
    }
}
