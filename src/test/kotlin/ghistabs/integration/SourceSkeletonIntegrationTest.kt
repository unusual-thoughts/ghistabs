package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.defaultContext
import ghistabs.harvest.Harvester
import ghistabs.parse.StabReader
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * Reconstruct a source-code skeleton per file mentioned by the binary's
 * stabs N_SOL / N_SLINE / N_FUN records:
 *
 * - One skeleton file per source filename (`build/test-output/skeletons/
 *   <fixture>/<sanitised-path>.cpp`).
 * - At each function's `startLine` we emit its declaration (from the
 *   stab symbol name minus the `:` type suffix).
 * - At each line that has an N_SLINE entry we emit a one-line `// 0xADDR`
 *   comment so the reader can cross-reference the disassembly.
 * - Function bodies are bracketed `{` / `}` based on the first and last
 *   N_SLINE line numbers that fall inside the function's address range.
 *
 * The test is intentionally a probe / artifact-producer rather than an
 * assertion harness — it dumps to disk and only asserts that at least
 * one skeleton was written.
 */
@Tag("integration")
class SourceSkeletonIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @ValueSource(strings = ["bouniafbouniaf.exe", "bouniaf.exe", "xmltest", "box2d_tests"])
    fun writeSkeletons(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        val loadResults = ProgramLoader.builder()
            .source(fixture)
            .compiler(if (fixture.extension.lowercase() == "exe") "mingw" else null)
            .log(log).monitor(monitor).load()
        try {
            val program = loadResults.getPrimaryDomainObject(this)
            val ctx = program.defaultContext()
            val reader = StabReader.fromProgram(program)!!
            val harvest = program.runTransaction("skeleton-harvest") {
                Harvester(monitor, ctx.sink, ctx.resolver).passA(reader.records)
            }

            val outDir = File("build/test-output/skeletons/${fixture.nameWithoutExtension}").apply { mkdirs() }

            // Group all source filenames (from line entries + functions) →
            // emit one skeleton per file. Functions and lines may live in
            // different files for the same CU (header methods, etc.).
            val sources = (harvest.lineEntries.keys + harvest.openFunctions.mapNotNull { it.sourceFile })
                .filter { it.isNotEmpty() }
                .toSet()

            var written = 0
            for (source in sources) {
                val skeleton = renderSkeleton(source, harvest)
                if (skeleton.isBlank()) continue
                val safeName = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").trim('_')
                File(outDir, "$safeName.cpp").writeText(skeleton)
                written++
            }
            println("SourceSkeleton[$binaryName]: ${sources.size} sources, $written skeletons → $outDir")
            assumeTrue(written > 0, "no skeletons produced (no N_SOL/N_SLINE in this binary?)")
        } finally {
            loadResults.close()
        }
    }

    private fun renderSkeleton(source: String, harvest: ghistabs.harvest.Harvest): String {
        val funcs = harvest.openFunctions
            .filter { it.sourceFile == source && it.startLine > 0 }
            .sortedBy { it.startLine }
        val lines = harvest.lineEntries[source].orEmpty()
        if (funcs.isEmpty() && lines.isEmpty()) return ""

        // For each function infer its end line: largest line in lineEntries
        // whose address falls in [func.addr, func.addr + sizeBytes).
        data class FuncRange(val func: ghistabs.harvest.OpenFunction, val endLine: Int)
        val ranges = funcs.map { f ->
            val lo = f.addr.offset
            val hi = lo + f.sizeBytes
            val end = lines
                .filter { it.addr.offset in lo until hi }
                .maxOfOrNull { it.line }
                ?: f.startLine
            FuncRange(f, end)
        }

        val maxLine = (ranges.maxOfOrNull { it.endLine } ?: 0)
            .coerceAtLeast(lines.maxOfOrNull { it.line } ?: 0)
        if (maxLine == 0) return ""

        // One entry per output line: file-level structure first.
        val out = Array(maxLine + 1) { mutableListOf<String>() }

        // Comments at every N_SLINE line.
        for ((line, addr) in lines.distinctBy { it.line to it.addr.offset }) {
            if (line in 1..maxLine) out[line] += "// 0x${addr.offset.toString(16).padStart(8, '0')}"
        }

        // Function open/close brackets.
        for ((f, endLine) in ranges) {
            val sig = signatureFor(f) ?: "// ${f.name}"
            out[f.startLine].add(0, "$sig {")
            if (endLine != f.startLine && endLine in 1..maxLine) {
                out[endLine] += "}  // end ${f.decl.name}"
            }
        }

        return buildString {
            append("// Auto-generated from stabs N_SOL/N_SLINE/N_FUN records.\n")
            append("// Source: $source\n")
            append("// Functions: ${funcs.size}, line entries: ${lines.size}\n\n")
            for (line in 1..maxLine) {
                if (out[line].isEmpty()) continue
                for (item in out[line]) append("/*L${line.toString().padStart(4)}*/ $item\n")
            }
        }
    }

    /** Best-effort C++-style declaration from the stab function name. */
    private fun signatureFor(f: ghistabs.harvest.OpenFunction): String? {
        // The name we store is the mangled symbol (`_Z…`). Demangle for a
        // readable declaration; fall back to the raw mangled form.
        val mangled = f.name
        val demangled = runCatching {
            ghidra.app.util.demangler.DemanglerUtil.demangle(mangled)?.signature
        }.getOrNull()
        return demangled ?: "// $mangled"
    }
}
