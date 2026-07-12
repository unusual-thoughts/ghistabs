package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.HullDisassemblyAnalyzer
import ghistabs.StabsAnalyzer
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/** How much undefined-code-inside-function-hulls remains, with HullDisassemblyAnalyzer on vs off? */
@Tag("integration")
class HullDisasmProbeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(booleans = [false, true])
    fun hullRecoversInFunctionCode(hullEnabled: Boolean) {
        val fixture = File("src/test/resources/binaries/bouniafbouniaf.exe")
        assumeTrue(fixture.exists(), "fixture absent")
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder().source(fixture).compiler("gcc").log(MessageLog()).monitor(monitor).load()
            .use { loadResults ->
                val program: Program = loadResults.getPrimaryDomainObject(this)
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                program.runTransaction("opts") {
                    val opts = program.getOptions(Program.ANALYSIS_PROPERTIES)
                    opts.setBoolean(StabsAnalyzer().name, false) // isolate from the import
                    opts.setBoolean(HullDisassemblyAnalyzer.NAME, hullEnabled)
                }
                mgr.reAnalyzeAll(null)
                program.runTransaction("analyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }

                val fm = program.functionManager
                var runs = 0
                var bytes = 0L
                val exec = program.memory.executeSet
                for (range in program.listing.getUndefinedRanges(exec, false, monitor)) {
                    val f = fm.getFunctionContaining(range.minAddress)
                        ?: fm.getFunctions(range.minAddress, false).let { if (it.hasNext()) it.next() else null }
                    if (f != null && range.minAddress <= f.body.maxAddress) {
                        runs++
                        bytes += range.length
                    }
                }
                println("[hull=$hullEnabled] undefined-in-hull: $runs runs, $bytes bytes")
            }
    }
}
