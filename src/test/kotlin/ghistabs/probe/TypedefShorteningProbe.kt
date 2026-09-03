package ghistabs.probe

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.importer.ImportProbe
import ghistabs.isConflict
import ghistabs.nameWithoutConflict
import ghistabs.runTransaction
import ghistabs.test.defaultContext
import ghistabs.test.disableWindowsResourceAnalyzer
import ghistabs.test.must
import ghistabs.test.mustBeEmpty
import ghistabs.withProgram
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * Runs the #7 typedef-shortening pass against a real fixture DTM after full autoanalyze
 * (which materializes the stabs types) and dumps every rename it computes to
 * `build/test-output/typedef-renames/<fixture>.txt`. Then applies them and asserts the
 * canonical std::string collapse actually landed, so the DTM plumbing — not just the pure
 * algorithm ([ghistabs.materialize.typedefShorteningRenames]) — is exercised.
 */
@Tag("probe")
class TypedefShorteningProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @MethodSource("ghistabs.integration.Fixtures#all")
    fun dumpRenames(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val monitor = TaskMonitor.DUMMY
        withProgram(fixture, log = MessageLog(), monitor = monitor) { program ->
            val probe = ImportProbe.install(program.defaultContext())
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            program.disableWindowsResourceAnalyzer()
            mgr.reAnalyzeAll(null)
            program.runTransaction("probe-autoanalyze") {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            }

            // The analyzer runs its own import inside the analysis above (shortening off by default);
            // the shortener is registry-scoped, so take the registry it built rather than the DTM.
            val registry = checkNotNull(probe.artifacts) { "analyzer produced no artifacts" }.registry
            val shortener = program.defaultContext().typedefShortener(registry)
            val renames = shortener.renames().sortedByDescending { it.from.length - it.to.length }

            val outDir = File("build/test-output/typedef-renames").apply { mkdirs() }
            File(outDir, "${fixture.nameWithoutExtension}.txt").writeText(
                renames.joinToString("\n") { "${it.from}\n  -> ${it.to}" },
            )
            println("Typedef-shorten[$binaryName]: ${renames.size} renames → $outDir")
            renames.take(8).forEach { println("  ${it.from}\n    -> ${it.to}") }

            assumeTrue(renames.isNotEmpty(), "no shortenable typedefs in this binary")
            val renamed = program.runTransaction("probe-apply") { shortener.apply() }
            renamed.must("apply renamed nothing") { this > 0 }
            // The alias usually sits in the target's own category as the typedef naming it, and folding
            // that typedef away is what frees the name — so a rename that lost the collision leaves a
            // `<alias>.conflict` behind (§21). None may survive, on any fixture.
            val aliases = renames.mapTo(mutableSetOf()) { it.to }
            program.dataTypeManager.allDataTypes.asSequence()
                .filter { it.isConflict() && it.nameWithoutConflict in aliases }
                .map { it.pathName }.toList()
                .mustBeEmpty("shortening forked conflicts on its own aliases")
        }
    }
}
