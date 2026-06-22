package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.data.Structure
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer
import ghistabs.StabsOptions
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.importer.ImportContext
import ghistabs.importer.StaticContexts
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Per-struct probe: dump the field tree for bouniaf (and any other
 * named structs) so we can spot holes / zero-length-stub leaks / wrong
 * base sizes directly.
 */
@Tag("integration")
class bouniafProbeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun probe() {
        val fixture = File("src/test/resources/binaries/bouniafbouniaf.exe")
        assumeTrue(fixture.exists(), "fixture absent")
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        val loadResults = ProgramLoader.builder()
            .source(fixture).compiler("mingw").log(log).monitor(monitor).load()
        try {
            val program = loadResults.getPrimaryDomainObject(this)
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            val ctx = ImportContext(
                program,
                monitor,
                StabsOptions(logDegradations = true),
                CapturingSink(),
                StabsDiagnostics(),
            )
            StaticContexts.install(ctx)
            val options = program.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES)
            program.runTransaction("disable-stabs-analyzer") {
                options.setBoolean(StabsAnalyzer().name, false)
            }
            mgr.initializeOptions()
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            }
            program.runTransaction("stabs-analyze") {
                StabsAnalyzer().run(ctx)
            }

            val out = File("build/degradations/bouniaffile.csymlexstream-probe.txt")
            out.parentFile.mkdirs()
            out.bufferedWriter().use { w ->
                for (target in listOf("bouniaf", "bouniaf", "RecoverySet")) {
                    val matches = program.dataTypeManager.allDataTypes.asSequence()
                        .filterIsInstance<Structure>()
                        .filter { it.name == target }
                        .toList()
                    w.write("=== $target — ${matches.size} match(es) ===\n")
                    for (s in matches) {
                        w.write("\n${s.categoryPath}/${s.name} (len=${s.length}, ${s.numComponents} components)\n")
                        for (c in s.components) {
                            val fname = c.fieldName ?: "<unnamed>"
                            val mark = if (c.dataType.name.startsWith("undefined")) "  *HOLE*" else ""
                            w.write(
                                "  +${c.offset.toString().padStart(
                                    4,
                                )} ${fname.padEnd(
                                    28,
                                )} ${c.dataType.pathName} (${c.dataType::class.simpleName}, ${c.length}b)$mark\n",
                            )
                        }
                    }
                    w.write("\n")
                }

                w.write("\n=== relevant counters ===\n")
                val counters = ctx.diagnostics.snapshotCounters()
                for (k in listOf(
                    "inheritance-applied",
                    "inheritance-failed",
                    "base-skipped-zero-size",
                    "vptr-skipped-inherited",
                )) {
                    w.write("  $k = ${counters[k] ?: 0}\n")
                }
                for ((k, v) in counters) {
                    if ("CSymLex" in k || k.startsWith("degraded-") && v > 0) {
                        w.write("  $k = $v\n")
                    }
                }

                w.write("\n=== ALL degradations (${ctx.diagnostics.snapshotDegradations().size}) ===\n")
                for (d in ctx.diagnostics.snapshotDegradations()) {
                    w.write("  [${d.category}] ${d.context} :: ${d.detail}\n")
                }
                w.write("\n=== sink log entries mentioning bouniaf ===\n")
                val sink = ctx.log as CapturingSink
                for (line in sink.lines) {
                    val msg = line.msg ?: continue
                    if ("bouniaf" in msg) w.write("  [${line.tag}] $msg\n")
                }

                w.write("\n=== Harvest TypeAsts for bouniaf + bouniaf + everything they ref ===\n")
                val reader = ghistabs.parse.StabReader.fromProgram(program)!!
                val freshHarvest = program.runTransaction("probe-harvest") {
                    ghistabs.harvest.Harvester(monitor, ctx.sink, ctx.resolver).passA(reader.records)
                }
                val csymAsts = freshHarvest.typeAsts.values.filter { it.name == "bouniaf" }
                val clxAsts = freshHarvest.typeAsts.values.filter { it.name == "bouniaf" }
                w.write("bouniaf variants: ${csymAsts.size}\n")
                for (a in csymAsts) {
                    val body = a.body as? ghistabs.parse.TypeDecl.Struct
                    w.write(
                        "  id=${a.id} size=${body?.sizeBytes} bases=${body?.bases?.size} fields=${body?.fields?.size}\n",
                    )
                    body?.bases?.forEach { base ->
                        w.write("    base @+${base.offsetBits / 8}: ${base.type}\n")
                    }
                }
                w.write("bouniaf variants: ${clxAsts.size}\n")
                for (a in clxAsts) {
                    val body = a.body as? ghistabs.parse.TypeDecl.Struct
                    w.write("  id=${a.id} size=${body?.sizeBytes} bases=${body?.bases?.size}\n")
                }
            }
            println("Wrote probe to ${out.absolutePath}")
        } finally {
            loadResults.close()
        }
    }
}
