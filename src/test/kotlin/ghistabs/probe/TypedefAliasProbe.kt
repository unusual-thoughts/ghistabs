package ghistabs.probe

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.importer.ImportProbe
import ghistabs.materialize.resolveRef
import ghistabs.runTransaction
import ghistabs.test.defaultContext
import ghistabs.test.disableWindowsResourceAnalyzer
import ghistabs.withProgram
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/** Every typedef alias the shortener could use: how many ASTs, which targets, which are xref stubs. */
@Tag("probe")
class TypedefAliasProbe : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @MethodSource("ghistabs.integration.Fixtures#all")
    fun dumpAliases(binaryName: String) {
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
            val registry = checkNotNull(probe.artifacts).registry
            val out = File("build/test-output/typedef-aliases/$binaryName.txt")
            out.parentFile.mkdirs()
            out.printWriter().use { w ->
                w.println("alias\tasts\tdistinctTargets\tstubTargets\ttargets")
                for ((alias, asts) in registry.types.namedTypedefs) {
                    val targets = asts.map { registry.resolveRef(it.body) }
                    val names = targets.map { it?.name ?: "<unresolved>" }.toSet()
                    val stubs = targets.count { it != null && it in registry.xrefStubs }
                    w.println(
                        "$alias\t${asts.size}\t${names.size}\t$stubs\t" +
                            names.joinToString(" | ") { it.take(90) },
                    )
                }
            }
            println("[aliases] $binaryName -> ${out.path}")
        }
    }
}
