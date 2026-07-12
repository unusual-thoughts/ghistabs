package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.address.Address
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.defaultContext
import ghistabs.importer.stabAddress
import ghistabs.parse.StabReader
import ghistabs.parse.StabType
import ghistabs.runTransaction
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * Validates the function-relative address heuristic ([stabAddress]) on real fixtures: every
 * `N_SLINE` / `N_LBRAC` / `N_RBRAC` record, resolved against its enclosing `N_FUN`, must land inside
 * *some* Ghidra-recognised function. Pins the block-scope / line-number rebasing against an
 * independent oracle (disassembly-derived function bounds) — a value left un-rebased resolves to a
 * tiny address in no function. Not the *enclosing* function specifically: gcc clones ctors/dtors,
 * so one stab function's line range legitimately spans sibling clone functions.
 */
@Tag("integration")
class FuncRelativeAddressIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(
        strings = ["xapasmcsr.exe", "xmltest", "appquery.exe", "box2d_tests", "packfile.exe", "unpackfile.exe"],
    )
    fun funcRelativeAddressesLandInTheirFunction(binaryName: String) {
        val filter = System.getProperty("fixtureFilter").orEmpty()
        assumeTrue(filter.isEmpty() || filter == binaryName, "fixture filtered out by -Pfixture")
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler(if (fixture.extension.lowercase() == "exe") "gcc" else null)
            .log(MessageLog()).monitor(monitor).load().use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                mgr.initializeOptions()
                mgr.reAnalyzeAll(null)
                program.runTransaction("analyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }

                val ctx = program.defaultContext()
                val resolver = ctx.resolver
                val fm = program.functionManager
                val listing = program.listing
                val reader = StabReader.fromProgram(program)
                assumeTrue(reader != null, "no .stab in $binaryName")

                var funcStart: Address? = null
                var checked = 0
                var correctFn = 0
                var otherFn = 0
                var noFnWithInsn = 0
                var noFnNoInsn = 0
                val notCode = mutableListOf<String>()
                for (rec in reader!!.physicalRecords()) {
                    when (rec.type) {
                        StabType.N_FUN ->
                            funcStart = rec.name.ifEmpty { null }?.let { resolver.buildAddress(rec.value) }

                        StabType.N_SLINE, StabType.N_LBRAC, StabType.N_RBRAC -> {
                            val fs = funcStart ?: continue // only records the stabs place inside a function
                            val target = resolver.stabAddress(rec.value, fs)
                            checked++
                            val enclosing = fm.getFunctionContaining(fs)
                            val hit = fm.getFunctionContaining(target)
                            when {
                                hit != null && hit == enclosing -> correctFn++
                                hit != null -> otherFn++
                                // no function — did Ghidra at least disassemble code here? (gcc puts
                                // EH landing pads / cold fragments outside the function body)
                                listing.getInstructionContaining(target) != null -> noFnWithInsn++
                                else -> noFnNoInsn++
                            }
                            if (program.memory.getBlock(target)?.isExecute != true) {
                                notCode += "${rec.type} @${rec.index} value=0x${rec.value.toString(16)} → " +
                                    "$target (from $fs)"
                            }
                        }

                        else -> {}
                    }
                }

                val counters = ctx.diagnostics.snapshotCounters()
                println(
                    "[$binaryName] func-relative landing (checked=$checked): correct-fn=$correctFn " +
                        "other-fn=$otherFn no-fn+insn=$noFnWithInsn no-fn+no-insn=$noFnNoInsn",
                )
                println(
                    "[$binaryName] stab-value branch: func-relative=${counters["stab-value-func-relative"] ?: 0} " +
                        "absolute=${counters["stab-value-absolute"] ?: 0}",
                )

                assumeTrue(checked > 0, "no func-relative records in $binaryName")
                assertTrue(
                    notCode.isEmpty(),
                    "func-relative stab values resolved outside executable code in $binaryName " +
                        "(${notCode.size}/$checked):\n${notCode.take(20).joinToString("\n")}",
                )
            }
    }
}
