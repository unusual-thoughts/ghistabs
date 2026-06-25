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

            val out = File("build/test-output/degradations/xmltest.probe.txt")
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

                w.write("\n=== Source-attribution census ===\n")
                val bySource = harvest.typeAsts.keys.groupBy { id ->
                    val s = id.toString()
                    s.substring(1, s.lastIndexOf(','))
                }
                for ((src, ids) in bySource.toSortedMap(compareBy { it })) {
                    w.write("  $src: ${ids.size} ids\n")
                }

                w.write("\n=== Raw stab records under each N_SO scope ===\n")
                var curSo = "(unknown)"
                val perSoIds = mutableMapOf<String, MutableSet<Int>>()
                val perSoBincls = mutableMapOf<String, MutableList<String>>()
                for (rec in reader.records) {
                    when (rec.type.name) {
                        "N_SO" -> {
                            if (rec.name.isNotEmpty()) {
                                curSo = rec.name
                                w.write("[N_SO] -> $curSo\n")
                            } else {
                                w.write("[N_SO] (end of $curSo)\n")
                            }
                        }

                        "N_BINCL" -> {
                            w.write("  [N_BINCL] $curSo includes ${rec.name}\n")
                            perSoBincls.getOrPut(curSo) { mutableListOf() }.add(rec.name)
                        }

                        "N_EXCL" -> w.write("  [N_EXCL] $curSo reuses ${rec.name}\n")

                        "N_LSYM" -> {
                            val s = rec.name
                            val m = Regex("""^([^:]*):.*?\(0,(\d+)\)=""").find(s)
                            if (m != null) {
                                val n = m.groupValues[2].toInt()
                                perSoIds.getOrPut(curSo) { mutableSetOf() }.add(n)
                            }
                        }
                    }
                }
                w.write("\n=== N_LSYM (0,N) bindings per CU ===\n")
                for ((cu, ns) in perSoIds) {
                    w.write(
                        "  $cu: ${ns.size} N_LSYM bindings (0,N) — sample: ${ns.sorted().take(40).joinToString(",")}\n",
                    )
                }

                w.write("\n=== Raw N_LSYM records under tinyxml2.cpp scope mentioning (0,25)= ===\n")
                curSo = "(none)"
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        curSo = if (rec.name.isNotEmpty()) rec.name else "(none)"
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if (rec.type.name != "N_LSYM") continue
                    if ("(0,25)=" in rec.name || "(0,89)=" in rec.name || "(0,27)=" in rec.name) {
                        w.write("  ${rec.name.take(240)}\n")
                    }
                }

                w.write("\n=== Raw stabs in tinyxml2.cpp CU defining ANY of these inline (sample) ===\n")
                curSo = "(none)"
                val targetInlines = listOf(25, 27, 89, 97).map { "(0,$it)=" }
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        curSo = if (rec.name.isNotEmpty()) rec.name else "(none)"
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if (rec.type.name != "N_LSYM" && rec.type.name != "N_GSYM" && rec.type.name != "N_PSYM") continue
                    if (targetInlines.any { it in rec.name }) {
                        w.write("  type=${rec.type.name} ${rec.name.take(240)}\n")
                    }
                }

                w.write("\n=== First 20 stabs in tinyxml2.cpp CU + first 30 N_LSYM/N_PSYM bindings ===\n")
                curSo = "(none)"
                var emitted = 0
                var nlsym = 0
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        if (rec.name.isNotEmpty()) {
                            curSo = rec.name
                            if (curSo == "/xml/tinyxml2.cpp") emitted = 0
                        } else {
                            if (curSo == "/xml/tinyxml2.cpp") {
                                w.write("[end tinyxml2.cpp]\n")
                                break
                            }
                            curSo = "(none)"
                        }
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if (rec.type.name == "N_BINCL" || rec.type.name == "N_EINCL" || rec.type.name == "N_EXCL") {
                        w.write("  type=${rec.type.name} ${rec.name.take(100)}\n")
                    } else if (rec.type.name == "N_LSYM") {
                        nlsym++
                        if (nlsym <= 30) w.write("  type=N_LSYM #$nlsym ${rec.name.take(160)}\n")
                    }
                    emitted++
                    if (emitted > 200) break
                }

                w.write("\n=== Looking for (0,25)= binding ANYWHERE in tinyxml2.cpp records ===\n")
                curSo = "(none)"
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        curSo = if (rec.name.isNotEmpty()) rec.name else "(none)"
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if ("(0,25)=" in rec.name) {
                        w.write("  type=${rec.type.name} ${rec.name.take(260)}\n")
                    }
                }

                w.write("\n=== Any include records in tinyxml2.cpp CU ===\n")
                curSo = "(none)"
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        curSo = if (rec.name.isNotEmpty()) rec.name else "(none)"
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if (rec.type.name in setOf("N_BINCL", "N_EINCL", "N_EXCL", "N_SOL")) {
                        w.write("  type=${rec.type.name} ${rec.name.take(120)}\n")
                    }
                }

                w.write("\n=== Any reference to (0,25) (def OR use) in tinyxml2.cpp ===\n")
                curSo = "(none)"
                var n = 0
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        curSo = if (rec.name.isNotEmpty()) rec.name else "(none)"
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if ("(0,25)" in rec.name) {
                        n++
                        if (n <= 15) w.write("  type=${rec.type.name} ${rec.name.take(200)}\n")
                    }
                }
                w.write("  total: $n records mention (0,25)\n")

                w.write("\n=== XMLNode name references in tinyxml2.cpp ===\n")
                curSo = "(none)"
                for (rec in reader.records) {
                    if (rec.type.name == "N_SO") {
                        curSo = if (rec.name.isNotEmpty()) rec.name else "(none)"
                        continue
                    }
                    if (curSo != "/xml/tinyxml2.cpp") continue
                    if (rec.name.startsWith("XMLNode:")) {
                        w.write("  type=${rec.type.name} ${rec.name.take(220)}\n")
                    }
                }

                w.write("\n=== All tinyxml2.cpp ids (n values) ===\n")
                val tinyxml2Ns = harvest.typeAsts.keys
                    .filter { it.toString().startsWith("[/xml/tinyxml2.cpp,") }
                    .mapNotNull { id ->
                        val s = id.toString()
                        val end = s.indexOf(']', s.lastIndexOf(','))
                        s.substring(s.lastIndexOf(',') + 1, end).toIntOrNull()
                    }
                    .sorted()
                w.write("  ${tinyxml2Ns.size} ids; range ${tinyxml2Ns.firstOrNull()}..${tinyxml2Ns.lastOrNull()}\n")
                w.write("  ids: ${tinyxml2Ns.joinToString(",")}\n")

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
