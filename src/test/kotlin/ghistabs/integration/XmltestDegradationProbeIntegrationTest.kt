package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvester
import ghistabs.importer.ImportContext
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabReader
import ghistabs.parse.TypeDecl
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * One-shot probe for the residual degradations on xmltest: dumps what the
 * harvest knows (or doesn't) about the type ids that the field-type /
 * placeholder-undefined-fields / dangling-ref entries reference, plus all
 * `DynArray*` ASTs to understand the field-dropped layout collision.
 */
@Tag("integration")
class XmltestDegradationProbeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun probeXmltest() {
        val fixture = File("src/test/resources/binaries/xmltest")
        assumeTrue(fixture.exists(), "fixture absent")

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        val loadResults = ProgramLoader.builder()
            .source(fixture)
            .log(log)
            .monitor(monitor)
            .load()
        try {
            val program = loadResults.getPrimaryDomainObject(this)
            val reader = StabReader.fromProgram(program)!!
            val ctx = ImportContext(
                program,
                monitor,
                StabsOptions(),
                CapturingSink(),
                StabsDiagnostics(),
            )
            val harvester = Harvester(monitor, ctx.sink, ctx.resolver)
            val harvest = program.runTransaction("xmltest-probe-harvest") {
                harvester.passA(reader.records)
            }

            val targetIds = listOf(
                "[/xml/tinyxml2.cpp,23]",
                "[/xml/tinyxml2.cpp,97]",
                "[/xml/tinyxml2.cpp,27]",
                "[/xml/tinyxml2.cpp,101]", // dangling-ref target
            )

            val out = File("build/degradations/xmltest.probe.txt")
            out.parentFile.mkdirs()
            out.bufferedWriter().use { w ->
                w.write("=== Unresolved type ids referenced from degradations ===\n\n")
                for (target in targetIds) {
                    w.write("Looking for $target...\n")
                    val matches = harvest.typeAsts.entries.filter { it.key.toString() == target }
                    if (matches.isEmpty()) {
                        w.write("  NOT IN HARVEST\n")
                        // Find any TypeAst whose source filename + n matches
                        val byN = harvest.typeAsts.entries
                            .filter { it.key.toString().contains("tinyxml2.cpp") }
                            .sortedBy { it.key.toString() }
                            .take(0)
                        if (byN.isNotEmpty()) {
                            w.write("  Sample tinyxml2.cpp ids in harvest:\n")
                            for (e in byN) {
                                w.write(
                                    "    ${e.key} → ${e.value.body::class.simpleName} name=${e.value.name}\n",
                                )
                            }
                        }
                    } else {
                        for (m in matches) w.write("  → ${m.value.body::class.simpleName} name=${m.value.name}\n")
                    }
                    w.write("\n")
                }

                w.write("\n=== All ids 20..40 and 90..110 in /xml/tinyxml2.cpp ===\n")
                val tinyxml2Ids = harvest.typeAsts.entries.filter {
                    it.key.toString().startsWith("[/xml/tinyxml2.cpp,")
                }
                fun nFromKey(k: GlobalTypeId): Int? {
                    val s = k.toString()
                    val comma = s.lastIndexOf(',')
                    val end = s.indexOf(']', comma)
                    return s.substring(comma + 1, end).toIntOrNull()
                }
                val tracked = (20..40).toList() + (90..110).toList()
                val byN = tinyxml2Ids.mapNotNull { e -> nFromKey(e.key)?.let { it to e } }.toMap()
                for (n in tracked.sorted().distinct()) {
                    val entry = byN[n]
                    if (entry != null) {
                        val b = entry.value.body
                        w.write("  ,$n → ${b::class.simpleName} name=${entry.value.name} body=$b\n".take(360) + "\n")
                    } else {
                        w.write("  ,$n → MISSING\n")
                    }
                }

                w.write("\n=== Parse error count: ${harvest.parseErrors} ===\n")
                w.write("\n=== Raw stab records for tinyxml2.cpp ids 23..40 + 95..109 ===\n")
                // Walk raw stab records, find N_LSYM/N_GSYM/etc. mentioning =(cu,n) and dump
                for (rec in reader.records) {
                    val s = rec.name
                    if (s.isEmpty()) continue
                    val cuIdRegex = Regex("""\(0,(2[3-9]|3\d|40|9[5-9]|10\d)\)=""")
                    if (cuIdRegex.containsMatchIn(s)) {
                        val type = rec.type.name
                        w.write("  type=$type str=${s.take(220)}\n")
                    }
                }

                w.write("\n=== ALL ids n=23..40 in harvest (any source) ===\n")
                for (n in 23..40) {
                    val matches = harvest.typeAsts.entries.filter { e ->
                        val s = e.key.toString()
                        val end = s.indexOf(']', s.lastIndexOf(','))
                        val nStr = s.substring(s.lastIndexOf(',') + 1, end)
                        nStr.toIntOrNull() == n
                    }
                    if (matches.isEmpty()) {
                        w.write("  n=$n: none\n")
                    } else {
                        w.write("  n=$n: ${matches.size} matches across sources:\n")
                        for (m in matches.take(5)) {
                            w.write("    ${m.key} → ${m.value.body::class.simpleName} name=${m.value.name}\n")
                        }
                    }
                }

                w.write("\n=== n=11 (should be XMLNode), n=10 (XMLDocument) — confirm sources ===\n")
                for (n in listOf(10, 11, 14, 17)) {
                    val ms = harvest.typeAsts.entries.filter { e ->
                        val s = e.key.toString()
                        val end = s.indexOf(']', s.lastIndexOf(','))
                        s.substring(s.lastIndexOf(',') + 1, end).toIntOrNull() == n
                    }
                    for (m in ms) w.write("  n=$n: ${m.key} → name=${m.value.name}\n")
                }

                w.write("\n=== All DynArray* ASTs ===\n")
                val dynArray = harvest.typeAsts.values.filter { (it.name ?: "").contains("DynArray") }
                for (a in dynArray) {
                    val sb = (a.body as? TypeDecl.Struct)?.sizeBytes
                    w.write("  id=${a.id} name='${a.name}' size=$sb ghidraName=${a.ghidraName}\n")
                }
            }
            println("Wrote probe to ${out.absolutePath}")

            program.release(this)
        } finally {
            loadResults.close()
        }
    }
}
