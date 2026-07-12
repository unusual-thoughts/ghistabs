package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.data.AlignmentDataType
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.runTransaction
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * Runs full auto-analysis (which fires [ghistabs.FillerByteAnalyzer]) and counts the `Alignment`
 * runs it produced — the only source of [AlignmentDataType] in the pipeline, so the count is exactly
 * the analyzer's hits. Reports run count + total bytes collapsed per fixture.
 */
@Tag("integration")
class FillerByteAnalyzerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(
        strings = ["xapasmcsr.exe", "xmltest", "appquery.exe", "box2d_tests", "packfile.exe", "unpackfile.exe"],
    )
    fun collapsesAlignmentPadding(binaryName: String) {
        val filter = System.getProperty("fixtureFilter").orEmpty()
        assumeTrue(filter.isEmpty() || filter == binaryName, "fixture filtered out by -Pfixture")
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler("gcc")
            .log(MessageLog()).monitor(monitor).load().use { loadResults ->
                val program: Program = loadResults.getPrimaryDomainObject(this)
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(null)
                program.runTransaction("analyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }

                val data = program.listing.getDefinedData(true)
                var runs = 0
                var bytes = 0L
                while (data.hasNext()) {
                    val d = data.next()
                    if (d.dataType is AlignmentDataType) {
                        runs++
                        bytes += d.length
                    }
                }
                println("[$binaryName] FillerByteAnalyzer: $runs alignment runs, $bytes bytes collapsed")

                assertTrue(runs > 0, "FillerByteAnalyzer collapsed no padding in $binaryName")
            }
    }
}
