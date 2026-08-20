package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.Harvester
import ghistabs.parse.StabReader
import ghistabs.parse.StabType
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * Is an N_SOL-derived run of text a real statement about where code came from?
 *
 * Each run is scored against the N_SLINE entries that land inside it: the run's bounds come from the
 * boundary *addresses*, the entries' file attribution comes from the *record order*, so the two
 * agreeing is not circular. A run whose entries mostly name some other file is an artifact of where
 * gcc's `Ltext<n>` label happened to be planted, not a partition of the text.
 *
 * Also counts what the runs cost to publish: boundaries that collide on one address (zero-length
 * runs), and the gap from each boundary to the next N_SLINE — a boundary emitted during the
 * post-body symbol flush is nowhere near the code it names.
 *
 * Parser + harvester only, no autoanalysis. Tagged `probe`; run via `probeDump`, writes
 * `build/test-output/textpartition/<fixture>.txt`. Companion to [ComdatProvenanceProbe]; §39 of
 * render-backlog.md is what both were written to settle.
 */
@Tag("probe")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TextPartitionProbe : AbstractGhidraHeadlessIntegrationTest() {
    private class Run(val start: Long, val file: String, val fromInclude: Boolean) {
        var end: Long = Long.MAX_VALUE
        var own = 0
        var foreign = 0
        val entries get() = own + foreign
    }

    @ParameterizedTest
    @MethodSource("ghistabs.IntegrationFixtures#all")
    fun dumpTextPartition(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder().source(fixture).compiler("gcc").log(MessageLog()).monitor(monitor).load()
            .use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val ctx = program.defaultContext()
                val records = StabReader.fromProgram(program)?.readAll()?.records
                assumeTrue(records != null, "no .stab section")
                val harvest = Harvester(ctx).harvest(records!!)

                // Boundaries sorted by address and closed by the next one — how `textPartition`
                // builds the runs, and the only reading under which they are disjoint at all.
                var cu = ""
                val boundaries = mutableListOf<Triple<Long, String, Boolean>>()
                for (rec in records!!) {
                    val include = rec.type == StabType.N_SOL
                    if (rec.type != StabType.N_SO && !include) continue
                    if (!include) cu = rec.name.ifEmpty { cu }
                    val file = rec.name.ifEmpty { cu }
                    if (rec.value != 0L && !file.endsWith('/')) boundaries += Triple(rec.value, file, include)
                }
                val sorted = boundaries.distinct().sortedBy { it.first }
                val collisions = sorted.zipWithNext().count { (a, b) -> a.first == b.first }
                val runs = sorted.zipWithNext().mapNotNull { (b, next) ->
                    Run(b.first, b.second, b.third).takeIf { next.first > b.first }?.also { it.end = next.first }
                }

                // Score each run by the line entries that land in it. Both sorted, walked in step.
                val entries = harvest.lineEntries
                    .flatMap { (src, es) -> es.map { it.addr.offset to src.path } }
                    .sortedBy { it.first }
                var i = 0
                for (run in runs) {
                    while (i < entries.size && entries[i].first < run.start) i++
                    var j = i
                    while (j < entries.size && entries[j].first < run.end) {
                        if (entries[j].second.endsWith(run.file.substringAfterLast('/'))) run.own++ else run.foreign++
                        j++
                    }
                }

                val sol = runs.filter { it.fromInclude && it.entries > 0 }
                val so = runs.filter { !it.fromInclude && it.entries > 0 }
                fun score(rs: List<Run>) = rs.sumOf { it.own } to rs.sumOf { it.foreign }
                val (solOwn, solForeign) = score(sol)
                val (soOwn, soForeign) = score(so)

                val out = File("build/test-output/textpartition/${fixture.nameWithoutExtension}.txt")
                out.parentFile.mkdirs()
                out.bufferedWriter().use { w ->
                    w.write("fixture: $binaryName\n")
                    w.write("runs: ${runs.size} (${runs.count { it.fromInclude }} from N_SOL), ")
                    w.write("zero-length (two boundaries on one address): $collisions\n")
                    w.write("line entries inside a run, by whether they name the run's own file:\n")
                    w.write("  N_SOL runs: own=$solOwn foreign=$solForeign")
                    w.write(" (${pct(solOwn, solOwn + solForeign)} agree, over ${sol.size} runs)\n")
                    w.write("  N_SO  runs: own=$soOwn foreign=$soForeign")
                    w.write(" (${pct(soOwn, soOwn + soForeign)} agree, over ${so.size} runs)\n\n")
                    w.write("worst N_SOL runs (most foreign entries):\n")
                    for (r in sol.sortedByDescending { it.foreign }.take(20)) {
                        w.write(
                            "  0x${r.start.toString(16)}..0x${r.end.toString(16)} own=${r.own} " +
                                "foreign=${r.foreign}  ${r.file}\n",
                        )
                    }
                }
                println(
                    "[$binaryName] N_SOL runs agree ${pct(solOwn, solOwn + solForeign)}, " +
                        "N_SO runs agree ${pct(soOwn, soOwn + soForeign)}, collisions=$collisions",
                )
                program.release(this)
            }
    }

    private fun pct(n: Int, total: Int) = if (total == 0) "n/a" else "${100 * n / total}%"
}
