package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.defaultContext
import ghistabs.harvest.Harvest
import ghistabs.harvest.Harvester
import ghistabs.harvest.OpenFunction
import ghistabs.parse.StabReader
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * Reconstruct a source-code skeleton per file mentioned by the binary's
 * stabs N_SOL / N_SLINE / N_FUN records. The output is structured so
 * each source line number lands on the same line in the skeleton —
 * blank lines pad gaps so a side-by-side view against the original
 * source aligns perfectly. Per line we emit:
 *
 *  - function declaration + `{` when the function starts on that line
 *    (from N_FUN's desc field);
 *  - one `// 0xADDR: <code-unit>` annotation per N_SLINE entry on the
 *    line (the address is now absolute — added to the function's start
 *    in the harvester — and we attach Ghidra's code-unit description so
 *    the comment shows the actual instruction / data the line maps to);
 *  - `}` on the line immediately after the last N_SLINE entry that
 *    falls inside the function's `[addr, addr+sizeBytes)` range, unless
 *    that would collide with the next function's start (in which case
 *    the close moves up onto the last-statement line).
 *
 * Probe semantics: writes to `build/test-output/skeletons/<fixture>/`
 * and only asserts that at least one skeleton was produced.
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
            // Run Ghidra's autoanalysis so getCodeUnitAt returns
            // disassembled instructions / typed data instead of raw
            // bytes when the skeleton renderer asks for the listing.
            // initializeOptions + scheduleOneTimeAnalysis is the
            // pattern from RegressionTest — startAnalysis alone is a
            // no-op on a freshly loaded program because nothing has
            // "changed" since the loader put bytes down.
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            program.runTransaction("skeleton-autoanalyze") {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            }
            val reader = StabReader.fromProgram(program)!!
            val harvest = program.runTransaction("skeleton-harvest") {
                Harvester(monitor, ctx.sink, ctx.resolver).passA(reader.records)
            }

            val outDir = File("build/test-output/skeletons/${fixture.nameWithoutExtension}").apply { mkdirs() }

            // Attribute each function to the source whose N_SLINE entries
            // cover the most of its address range. This is the
            // authoritative signal (gcc emits N_SOL("header") before
            // template instantiations' N_FUN and resets it before CU
            // functions), so std::pair::pair lands in stl_pair.h and
            // CParser::ParseSymbol lands in parse.cpp. Functions with
            // sizeBytes==0 or no covered N_SLINE drop out of every
            // skeleton — they have no place to go.
            val funcToSource = attributeFunctionsBySource(harvest)
            val sources = (harvest.lineEntries.keys + funcToSource.values)
                .filter { it.isNotEmpty() }
                .toSet()

            var written = 0
            for (source in sources) {
                val skeleton = renderSkeleton(source, harvest, program, funcToSource)
                if (skeleton.isBlank()) continue
                // Keep the source's own extension — don't append `.cpp`
                // (so e.g. `assemble.cpp` stays `assemble.cpp`, not
                // `assemble.cpp.cpp`; and `tinyxml2.h` keeps its `.h`).
                val safeName = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").trim('_')
                File(outDir, safeName).writeText(skeleton)
                written++
            }
            println("SourceSkeleton[$binaryName]: ${sources.size} sources, $written skeletons → $outDir")
            assumeTrue(written > 0, "no skeletons produced (no N_SOL/N_SLINE in this binary?)")
        } finally {
            loadResults.close()
        }
    }

    /**
     * Attribute each function to the source of its lowest-address
     * N_SLINE entry inside `[addr, addr+sizeBytes)`. The first line
     * entry corresponds to the function's prologue, which is always
     * emitted under the N_SOL active at N_FUN time — for
     * `std::vector::push_back` that's `stl_vector.h`, for
     * `CParser::Foo` that's `parse.cpp`.
     *
     * A count-based heuristic looks tempting but backfires on host
     * methods with heavily inlined std helpers (e.g. a CParser method
     * with five own lines and fifty inlined `vector::operator[]`
     * N_SLINEs gets misattributed to `stl_vector.h`).
     *
     * Functions with no covered N_SLINE (or `sizeBytes==0`) get no
     * attribution and silently drop from every skeleton.
     */
    private fun attributeFunctionsBySource(harvest: Harvest): Map<OpenFunction, String> {
        val out = mutableMapOf<OpenFunction, String>()
        for (f in harvest.openFunctions) {
            val lo = f.addr.address.offset
            val hi = lo + f.sizeBytes
            if (hi <= lo) continue
            var bestSrc: String? = null
            var bestAddr = Long.MAX_VALUE
            for ((src, entries) in harvest.lineEntries) {
                for (e in entries) {
                    val a = e.addr.address.offset
                    if (a in lo until hi && a < bestAddr) {
                        bestAddr = a
                        bestSrc = src
                    }
                }
            }
            bestSrc?.let { out[f] = it }
        }
        return out
    }

    private fun renderSkeleton(
        source: String,
        harvest: Harvest,
        program: Program,
        funcToSource: Map<OpenFunction, String>,
    ): String {
        val rawFuncs = harvest.openFunctions.filter { funcToSource[it] == source }
        val lines = harvest.lineEntries[source].orEmpty()
        if (rawFuncs.isEmpty() && lines.isEmpty()) return ""

        data class FuncRange(val func: OpenFunction, val startLine: Int, val endLine: Int)

        val ranges = rawFuncs.mapNotNull { f ->
            val lo = f.addr.address.offset
            val hi = lo + f.sizeBytes
            val inside = lines.filter { it.addr.address.offset in lo until hi }
            val start = inside.minOfOrNull { it.line } ?: return@mapNotNull null
            val end = inside.maxOfOrNull { it.line } ?: start
            FuncRange(f, start, end)
        }.sortedBy { it.startLine }
        val funcs = ranges.map { it.func }
        // Compute close-brace target line per function. Default: endLine+1
        // (closing braces usually live on the line after the last
        // statement). If that collides with a sibling function's start
        // line, put the close on endLine.
        val startLines = ranges.map { it.startLine }.toSet()
        val closeLineByFunc = ranges.associate { (f, _, end) ->
            f to if ((end + 1) in startLines) end else end + 1
        }

        val maxLine = sequenceOf(
            closeLineByFunc.values.maxOrNull() ?: 0,
            lines.maxOfOrNull { it.line } ?: 0,
            ranges.maxOfOrNull { it.startLine } ?: 0,
            ranges.maxOfOrNull { it.endLine } ?: 0,
        ).max()
        if (maxLine == 0) return ""

        // Layout: one bucket per source line; render exactly maxLine
        // output lines (blank where empty) so source line N == output
        // line N.
        val buckets = Array(maxLine + 1) { mutableListOf<String>() }

        // Comments at every N_SLINE line (dedupe by address — gcc
        // occasionally emits duplicates after optimisation).
        val seenPerLine = mutableMapOf<Int, MutableSet<Long>>()
        // For each line, determine whether it falls inside a function's
        // [startLine, closeLine] range so we can indent it like C++ source.
        val funcSpan = ranges.map { (f, start, _) ->
            val close = closeLineByFunc[f] ?: start
            start..close
        }

        fun inFunction(line: Int) = funcSpan.any { line in it }

        for (entry in lines) {
            val addrs = seenPerLine.getOrPut(entry.line) { mutableSetOf() }
            if (!addrs.add(entry.addr.address.offset)) continue
            if (entry.line !in 1..maxLine) continue
            val codeUnit = describeAddress(program, entry.addr.address)
            val addrHex = "0x" + entry.addr.address.offset.toString(16).padStart(8, '0')
            // Keep `L<line>` inside the comment so an alignment check
            // after manual edits is just `grep -nE '// L([0-9]+):' | awk
            // -F: '$1 != $2'`.
            val lineTag = "L" + entry.line.toString().padStart(4)
            val indent = if (inFunction(entry.line)) "    " else ""
            buckets[entry.line] += "$indent// $lineTag @ $addrHex${codeUnit?.let { ": $it" } ?: ""}"
        }

        // Type declaration markers — N_LSYM's `desc` carries the line
        // where a typedef/tag/local-type was declared. Emit a one-line
        // comment so the skeleton shows which types this file (or the
        // header it captures) declares.
        val typeDecls = harvest.typeAsts.values
            .filter { it.declSourceFile == source && it.declLine in 1..maxLine && it.name != null }
            .groupBy { it.declLine }
        for ((line, asts) in typeDecls) {
            val names = asts.mapNotNull { it.name }.distinct().take(3).joinToString(", ")
            val lineTag = "L" + line.toString().padStart(4)
            buckets[line] += "// $lineTag : typedef $names"
        }

        // Param + local + global declarations — N_PSYM / N_RSYM /
        // N_GSYM / N_LCSYM / N_STSYM desc. Cluster per (line, kind) and
        // dedupe by name so multiple inline methods sharing one
        // declaration line don't pile up identical comments. `this` is
        // filtered out — every method's first reg local is `this`, no
        // signal in seeing it 12× per line.
        data class DeclKey(val line: Int, val kind: String)

        val declNames = mutableMapOf<DeclKey, MutableSet<String>>()
        fun add(line: Int, kind: String, name: String) {
            if (line !in 1..maxLine) return
            if (name == "this") return
            declNames.getOrPut(DeclKey(line, kind)) { mutableSetOf() } += name
        }
        for (f in rawFuncs) {
            for (p in f.params) {
                if (p.sourceFile != source) continue
                val name = (p.body as? SymbolDecl.StackParam)?.name
                    ?: (p.body as? SymbolDecl.RegParam)?.name
                    ?: continue
                add(p.declLine, "param", name)
            }
            for (l in f.locals) {
                if (l.sourceFile != source) continue
                val (kind, name) = when (val d = l.body) {
                    is SymbolDecl.RegLocal -> "reg local" to d.name
                    is SymbolDecl.StackLocal -> "stack local" to d.name
                    else -> continue
                }
                add(l.declLine, kind, name)
            }
        }
        for ((_, syms) in harvest.symbolsByCu) {
            for (s in syms) {
                if (s.sourceFile != source) continue
                val name = when (val d = s.body) {
                    is SymbolDecl.Global -> d.name
                    is SymbolDecl.StaticVar -> d.name
                    else -> continue
                }
                val kind = when (s.recordType) {
                    StabType.N_GSYM -> "global"
                    StabType.N_LCSYM -> ".bss static"
                    StabType.N_STSYM -> ".data static"
                    StabType.N_ROSYM -> ".rodata static"
                    else -> "symbol"
                }
                add(s.declLine, kind, name)
            }
        }
        for ((key, names) in declNames) {
            val lineTag = "L" + key.line.toString().padStart(4)
            val joined = names.take(6).joinToString(", ") +
                if (names.size > 6) ", … (${names.size - 6} more)" else ""
            val indent = if (inFunction(key.line)) "    " else ""
            buckets[key.line] += "$indent// $lineTag : ${key.kind} $joined"
        }

        // Function openers at startLine. Tag with the source line so
        // alignment drift after edits is immediately obvious.
        for ((f, startLine, _) in ranges) {
            val sig = signatureFor(f)
            val lineTag = "L" + startLine.toString().padStart(4)
            buckets[startLine].add(0, "$sig {  /* $lineTag — opens ${f.decl.name} */")
        }
        // Function closers at chosen close line.
        for ((f, _, _) in ranges) {
            val closeLine = closeLineByFunc[f] ?: continue
            if (closeLine !in 1..maxLine) continue
            val lineTag = "L" + closeLine.toString().padStart(4)
            buckets[closeLine] += "}  /* $lineTag — closes ${f.decl.name} */"
        }

        return buildString {
            append("// Auto-generated from stabs N_SOL / N_SLINE / N_FUN records.\n")
            append("// Source: $source\n")
            append("// Functions: ${funcs.size}, line entries: ${lines.size}\n")
            // Header is N lines of preamble; pad the rest with blanks
            // so source-line N lands on output-line N + preamble.
            val preambleLines = 3
            repeat(preambleLines) { /* preamble lines already appended */ }
            for (line in 1..maxLine) {
                val bucket = buckets[line]
                if (bucket.isEmpty()) {
                    append('\n')
                } else if (bucket.size == 1) {
                    append(bucket.single())
                    append('\n')
                } else {
                    // Multiple items on one line: declaration + first
                    // comment, then continuation indented below so the
                    // PRIMARY line slot stays single-line.
                    append(bucket.first())
                    for (extra in bucket.drop(1)) {
                        append("  ")
                        append(extra)
                    }
                    append('\n')
                }
            }
        }
    }

    /**
     * Ghidra-listing description for [addr]: the primary symbol if any
     * (so a function entry shows as `foo:` and a data label as
     * `gGlobal:`), plus the code unit's printable form (instruction
     * mnemonic + operands, or the data type / value). Returns null if
     * nothing meaningful is at this address.
     */
    private fun describeAddress(program: Program, addr: Address): String? {
        val sym = program.symbolTable.getPrimarySymbol(addr)
            ?.takeIf { it.source != SourceType.DEFAULT }
            ?.name
        val body = when (val cu = program.listing.getCodeUnitAt(addr)) {
            is Instruction -> "${cu.mnemonicString} ${cu.toString().substringAfter(' ', "").trim()}".trim()

            is Data -> {
                val value = runCatching { cu.value?.toString() }.getOrNull()
                val type = cu.dataType.name
                listOfNotNull(type, value).joinToString(" = ")
            }

            else -> null
        }
        return when {
            sym != null && body != null -> "$sym → $body"
            sym != null -> sym
            body != null -> body
            else -> null
        }
    }

    /**
     * Best-effort C++-style declaration from the stab function name.
     * Ghidra's `DemangledFunction.signature` prepends Ghidra's guess at
     * the calling convention (often the wrong `__rustcall` for Itanium
     * `_ZN…` symbols because the unified demangler can't distinguish
     * gcc-Itanium from legacy-Rust at the entry point). Strip any
     * leading `__*call ` token and rebuild from the demangler's name +
     * params instead.
     */
    private fun signatureFor(f: OpenFunction): String {
        val mangled = f.name
        val demangled = runCatching {
            @Suppress("DEPRECATION")
            ghidra.app.util.demangler.DemanglerUtil.demangle(mangled)
        }.getOrNull() ?: return "// $mangled"
        val raw = demangled.signature ?: return "// $mangled"
        // Drop a leading `__<conv>call ` prefix Ghidra inserted.
        return Regex("""^__[a-zA-Z]+call\s+""").replace(raw, "")
    }
}
