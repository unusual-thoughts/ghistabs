package ghistabs.integration

import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.defaultContext
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeResolver
import ghistabs.parse.StabReader
import ghistabs.render.Renderer
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
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
 * Probe semantics: writes to `build/test-output/skeletons/<fixture>/`
 * and only asserts that at least one skeleton was produced.
 */
@Tag("integration")
class SourceSkeletonIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(strings = ["bouniafbouniaf.exe", "xmltest", "bouniaf.exe", "box2d_tests"])
    fun writeSkeletons(binaryName: String) = runPipeline(binaryName, decompile = false)

    @ParameterizedTest
    @ValueSource(
        strings = ["bouniafbouniaf.exe", "xmltest", "bouniaf.exe", "box2d_tests", "bouniaf.exe", "unbouniaf.exe"],
    )
    fun writeDecompilations(binaryName: String) = runPipeline(binaryName, decompile = true)

    private fun runPipeline(binaryName: String, decompile: Boolean) {
        val filter = System.getProperty("fixtureFilter").orEmpty()
        assumeTrue(filter.isEmpty() || filter == binaryName, "fixture filtered out by -Pfixture")
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")
        val outDirName = if (decompile) "decomps" else "skeletons"
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler(if (fixture.extension.lowercase() == "exe") "gcc" else null)
            .log(log).monitor(monitor).load().use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val ctx = program.defaultContext()
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(null)
                program.runTransaction("skeleton-autoanalyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }
                val reader = StabReader.fromProgram(program)!!
                val harvest = program.runTransaction("skeleton-harvest") {
                    Harvester(monitor, ctx.sink, ctx.resolver).passA(reader.records)
                }

                val outDir = File("build/test-output/$outDirName/${fixture.nameWithoutExtension}")
                if (outDir.exists()) {
                    val oldDir = File("${outDir.path}.old")
                    oldDir.deleteRecursively()
                    outDir.renameTo(oldDir)
                }
                outDir.mkdirs()

                val typeResolver = TypeResolver(harvest)
                val sources = (
                    harvest.lineEntries.keys +
                        typeResolver.functionSource.values +
                        harvest.typeAsts.values.map {
                            typeResolver.multiSourceHeaderHints[it.name] ?: it.id.source.filename
                        }
                    )
                    .filter { it.isNotEmpty() }
                    .toSet()

                val decomp = if (decompile) {
                    DecompInterface().apply {
                        // Widen output so long template-typed declarations aren't wrapped by the
                        // decompiler into orphan continuation lines (e.g. a bare `;`).
                        setOptions(DecompileOptions().apply { setMaxWidth(10_000) })
                        openProgram(program)
                    }
                } else {
                    null
                }
                try {
                    // Transaction: renderSkeleton defines terminated strings at undefined
                    // pointer targets it meets while rendering constant values.
                    val written = program.runTransaction("skeleton-render") {
                        var w = 0
                        for (source in sources) {
                            val out = Renderer(typeResolver, program, decomp).renderSkeleton(source)
                            if (out.isBlank()) continue
                            val safeName = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").trim('_')
                            File(outDir, safeName).writeText(out)
                            w++
                        }
                        w
                    }
                    println("Pipeline[$binaryName, $outDirName]: ${sources.size} sources, $written files → $outDir")
                    assumeTrue(written > 0, "no output (no N_SOL/N_SLINE in this binary?)")
                } finally {
                    decomp?.dispose()
                }
            }
    }
}
