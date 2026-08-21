package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.Func
import ghistabs.harvest.Harvester
import ghistabs.harvest.hasHeaderExtension
import ghistabs.parse.StabReader
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * Do the copies of a COMDAT-merged body agree on which file it came from?
 *
 * A body several CUs claim at one address was folded by the linker from a definition they all
 * included, so each copy's own N_SLINEs are the only statement about where that definition lives.
 * If the copies agree, that file is evidence for the owning header ([ghistabs.harvest.HarvestIndex]'s
 * header hints could use it); if they disagree, the stabs carry no provenance for merged bodies and
 * the N_SOL-burst vote is the ceiling. §39 of render-backlog.md found `XVImage`'s merged destructor
 * clones naming `iostream` / `appimage.h` / `basic_string.h` / `gthr-default.h` across four CUs —
 * this probe measures how general that is, and whether template instantiations behave differently.
 *
 * Parser + harvester only: the harvest is a pure function of the records, so no autoanalysis and no
 * materialize/apply pass. A generator, not a pass/fail test — tagged `probe`, so it runs via
 * `probeDump`, writing `build/test-output/comdat/<fixture>.txt`.
 */
private val CU_RANGE_TAGS = listOf("unfinished-cu", "empty-cu-range", "inverted-cu-range")

@Tag("probe")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ComdatProvenanceProbe : AbstractGhidraHeadlessIntegrationTest() {
    /** One merged body: every CU's copy of it, and the file each copy attributes it to. */
    private data class Merged(val name: String, val copies: List<Func>) {
        /** A copy's own lowest-address line entry — what the header hints would read off it. */
        val distinct = copies.mapNotNull { c -> c.lineEntries.minByOrNull { it.addr.offset }?.source }.distinct()
        val agrees = distinct.size == 1
        val header = distinct.singleOrNull()?.filename?.hasHeaderExtension() == true
    }

    @ParameterizedTest
    @MethodSource("ghistabs.IntegrationFixtures#all")
    fun dumpComdatProvenance(binaryName: String) {
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

                // The other derivation, from what each CU declared: a body outside its own CU's span
                // — or in a CU that declared none, its code having gone to COMDAT sections — was not
                // in that CU's ordinary text. Broader than a multi-CU claim, which is the subset the
                // linker demonstrably folded, and the two should never contradict (§39).
                val bySpan = harvest.functions.groupingBy { f ->
                    harvest.cuSpans[f.cu]?.let { if (it.contains(f.addr)) "plain .text" else "outside its span" }
                        ?: "CU declared no text"
                }.eachCount()

                // Why a CU has no span, straight off the sink: `addressRange()` says which degenerate
                // case it was and names the CU, where a count could only say how many.
                val verdicts = ctx.terminal.lines.filter { it.tag in CU_RANGE_TAGS }

                val byAddr = harvest.functions.groupBy { it.addr }
                val shared = byAddr.filterValues { copies -> copies.mapTo(mutableSetOf()) { it.cu }.size > 1 }
                val merged = shared.values
                    .groupBy { copies -> copies.first().name }
                    .map { (name, groups) -> Merged(name, groups.flatten()) }
                    .sortedByDescending { it.copies.size }
                val (agree, disagree) = merged.partition { it.agrees }

                val out = File("build/test-output/comdat/${fixture.nameWithoutExtension}.txt")
                out.parentFile.mkdirs()
                out.bufferedWriter().use { w ->
                    w.write("fixture: $binaryName\n")
                    w.write("function addresses: ${byAddr.size}, claimed by >1 CU: ${shared.size}\n")
                    w.write("merged symbols: ${merged.size}\n")
                    w.write("  copies agree on a source: ${agree.size} (${agree.count { it.header }} name a header)\n")
                    w.write("  copies disagree:          ${disagree.size}\n")
                    w.write("what each CU declared, per function:\n")
                    for ((verdict, n) in bySpan.entries.sortedByDescending { it.value }) {
                        w.write("  ${verdict.padEnd(20)} $n\n")
                    }
                    val contradictions = merged.count { m ->
                        m.copies.any { harvest.cuSpans[it.cu]?.contains(it.addr) == true }
                    }
                    w.write("  merged bodies their own CU claims as plain .text: $contradictions\n")
                    w.write("CUs with no span, by why (CuContext.addressRange()):\n")
                    for (tag in CU_RANGE_TAGS) {
                        w.write("  ${tag.padEnd(18)} ${verdicts.count { it.tag == tag }}\n")
                    }
                    for (v in verdicts) w.write("  $v\n")
                    w.write("\n")
                    for (m in merged) {
                        w.write("${m.copies.size}x ${if (m.agrees) "AGREE   " else "DISAGREE"} ${m.name}\n")
                        for (src in m.distinct) w.write("      $src\n")
                    }
                }
                println(
                    "[$binaryName] merged=${merged.size} agree=${agree.size} " +
                        "(header=${agree.count { it.header }}) disagree=${disagree.size} → ${out.absolutePath}",
                )
                program.release(this)
            }
    }
}
