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
import ghistabs.harvest.LineEntry
import ghistabs.harvest.OpenFunction
import ghistabs.materialize.BuiltinTable
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabReader
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
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
    @ValueSource(strings = ["bouniafbouniaf.exe"])
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
            val lineEntries = rerouteLineEntriesByFunc(harvest, funcToSource)
            val sources = (lineEntries.keys + funcToSource.values)
                .filter { it.isNotEmpty() }
                .toSet()

            var written = 0
            for (source in sources) {
                val skeleton = renderSkeleton(source, harvest, lineEntries, program, funcToSource)
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
     * gcc emits file-scope synthetic init/destruct wrappers
     * (`_GLOBAL__I_<sym>`, `_GLOBAL__D_<sym>`,
     * `__static_initialization_and_destruction_0`) at the CU's
     * end-of-file but under whatever N_SOL was last active — typically
     * the last `#include`d header. They belong to the CU that owns the
     * static they initialize, not to that header.
     */
    private fun isSyntheticInit(f: OpenFunction): Boolean {
        val n = f.name
        return n.startsWith("_GLOBAL__I_") ||
            n.startsWith("_GLOBAL__D_") ||
            n.startsWith("_GLOBAL__N_") ||
            n.startsWith("_Z41__static_initialization_and_destruction_0") ||
            n == "__static_initialization_and_destruction_0"
    }

    /**
     * Attribute each function to the source of its lowest-address
     * N_SLINE entry inside `[addr, addr+sizeBytes)`. The first line
     * entry corresponds to the function's prologue, which is always
     * emitted under the N_SOL active at N_FUN time — for
     * `std::vector::push_back` that's `stl_vector.h`, for
     * `CParser::Foo` that's `parse.cpp`.
     *
     * Exception: gcc synthetic init wrappers ([isSyntheticInit]) get
     * routed to their owning CU, since gcc lies about their N_SOL.
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
            if (isSyntheticInit(f)) {
                out[f] = f.cu.filename
                continue
            }
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

    /**
     * Reroute every N_SLINE entry to the source of the function that
     * contains it, when it has one. gcc occasionally emits a single
     * N_SLINE under a transient (wrong) N_SOL while its siblings in
     * the same function land under the right one — leaving stray
     * `// L N @ 0xADDR` comments orphaned in some unrelated header.
     * Anchoring on the host function gives uniform attribution across
     * a function's body. Entries outside every function range stay
     * where N_SOL put them.
     */
    private fun rerouteLineEntriesByFunc(
        harvest: Harvest,
        funcToSource: Map<OpenFunction, String>,
    ): Map<String, List<LineEntry>> {
        data class Reroute(val range: LongRange, val target: String)
        val reroutes = harvest.openFunctions
            .filter { it.sizeBytes > 0 && funcToSource[it] != null }
            .map {
                val lo = it.addr.address.offset
                Reroute(lo until lo + it.sizeBytes, funcToSource.getValue(it))
            }
        if (reroutes.isEmpty()) return harvest.lineEntries
        val out = mutableMapOf<String, MutableList<LineEntry>>()
        for ((src, entries) in harvest.lineEntries) {
            for (e in entries) {
                val addr = e.addr.address.offset
                val target = reroutes.firstOrNull { addr in it.range }?.target ?: src
                out.getOrPut(target) { mutableListOf() } += e
            }
        }
        return out
    }

    private fun renderSkeleton(
        source: String,
        harvest: Harvest,
        lineEntries: Map<String, List<LineEntry>>,
        program: Program,
        funcToSource: Map<OpenFunction, String>,
    ): String {
        val rawFuncs = harvest.openFunctions.filter { funcToSource[it] == source }
        val lines = lineEntries[source].orEmpty()
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

        fun lineTag(line: Int) = "// L" + line.toString().padStart(4)
        fun indentFor(line: Int) = if (inFunction(line)) "    " else ""

        // Type declarations — N_LSYM `:T`/`:t` `desc` carries the line
        // where a typedef / struct tag was declared. Render as C-ish
        // declarations: `struct X { … };` for tags, `typedef T Y;` for
        // aliases. Same alias name repeated at the same line (e.g.
        // `iterator` materialised from multiple template instantiations)
        // is deduped on (line, body-shape, name).
        data class TypeDeclKey(val line: Int, val name: String, val bodyKind: String)

        val seenTypeDecls = mutableSetOf<TypeDeclKey>()
        for (ast in harvest.typeAsts.values
            .filter { it.declSourceFile == source && it.declLine in 1..maxLine && it.name != null }
            .sortedBy { it.declLine }) {
            val line = ast.declLine
            val name = ast.name ?: continue
            val key = TypeDeclKey(line, name, ast.body::class.simpleName ?: "")
            if (!seenTypeDecls.add(key)) continue
            val decl = when (val b = ast.body) {
                is TypeDecl.Struct -> "${kindKeyword(b.kind)} $name; /* ${b.sizeBytes} bytes */"
                is TypeDecl.Enum -> "enum $name; /* ${b.members.size} members */"
                else -> "typedef ${renderType(b, harvest)} $name;"
            }
            buckets[line] += "${indentFor(line)}$decl  ${lineTag(line)}"
        }

        // Param + local + global declarations — N_PSYM / N_RSYM /
        // N_GSYM / N_LCSYM / N_STSYM `desc`. Dedupe per (line, name)
        // because the same template instantiated many times produces
        // duplicate `__val` / `__first` entries at the same header line.
        // `this` is filtered — no signal in seeing it 12× per line.
        data class DeclKey(val line: Int, val name: String)

        val seenDecls = mutableSetOf<DeclKey>()
        fun emitDecl(line: Int, name: String, type: TypeDecl<GlobalTypeId>, suffix: String) {
            if (line !in 1..maxLine) return
            if (name == "this") return
            if (!seenDecls.add(DeclKey(line, name))) return
            val rendered = "${renderType(type, harvest)} $name;"
            buckets[line] += "${indentFor(line)}$rendered  ${lineTag(line)} $suffix"
        }
        for (f in rawFuncs) {
            for (p in f.params) {
                if (p.sourceFile != source) continue
                when (val d = p.body) {
                    is SymbolDecl.StackParam -> emitDecl(p.declLine, d.name, d.type, "(param)")
                    is SymbolDecl.RegParam -> emitDecl(p.declLine, d.name, d.type, "(reg param)")
                    else -> {}
                }
            }
            for (l in f.locals) {
                if (l.sourceFile != source) continue
                when (val d = l.body) {
                    is SymbolDecl.RegLocal -> emitDecl(l.declLine, d.name, d.type, "(reg local)")
                    is SymbolDecl.StackLocal -> emitDecl(l.declLine, d.name, d.type, "(stack local)")
                    else -> {}
                }
            }
        }
        // For globals/statics, attribute by CU rather than by
        // `s.sourceFile`. gcc doesn't emit `N_SOL("bouniaffile.cpp")`
        // before each N_GSYM in the CU's opening declaration burst, so
        // `sourceFile` ends up pointing at whichever header N_SOL last
        // visited (typically the LAST `#include`d header — e.g.
        // stl_map.h). The CU key in `symbolsByCu` is authoritative.
        for ((cu, syms) in harvest.symbolsByCu) {
            if (cu != source) continue
            for (s in syms) {
                val suffix = when (s.recordType) {
                    StabType.N_GSYM -> "(global)"
                    StabType.N_LCSYM -> "(.bss static)"
                    StabType.N_STSYM -> "(.data static)"
                    StabType.N_ROSYM -> "(.rodata static)"
                    else -> "(symbol)"
                }
                when (val d = s.body) {
                    is SymbolDecl.Global -> emitDecl(s.declLine, d.name, d.type, suffix)
                    is SymbolDecl.StaticVar -> emitDecl(s.declLine, d.name, d.type, suffix)
                    else -> {}
                }
            }
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
            // Each item in a bucket goes on its own output line so
            // typedefs / declarations read as real C, not a single
            // 700-char run-on. To keep `// Lnnn` ≈ output-line N as
            // closely as possible, overflow lines are absorbed into the
            // next runs of blank source lines: a bucket with 5 items at
            // source-line 42 followed by 8 blank source lines emits
            // those 5 items then only 4 blanks (5−1=4 absorbed),
            // landing source-line 50 back on output-line 50.
            var debt = 0
            for (line in 1..maxLine) {
                val bucket = buckets[line]
                if (bucket.isEmpty()) {
                    if (debt > 0) debt-- else append('\n')
                } else {
                    for (item in bucket) {
                        append(item)
                        append('\n')
                    }
                    debt += bucket.size - 1
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
    private fun kindKeyword(k: AggrKind) = when (k) {
        AggrKind.STRUCT -> "struct"
        AggrKind.UNION -> "union"
        AggrKind.CLASS -> "class"
        AggrKind.ENUM -> "enum"
    }

    /**
     * Best-effort C-style rendering of a [TypeDecl]. Primitives go
     * through [BuiltinTable] so they come out as `int` / `uchar` /
     * `double` etc; named composite types are looked up by id in
     * [Harvest.typeAsts]. Depth-capped because cyclic types (gcc's
     * recursive `std::basic_string<…>::operator=` taking
     * `std::string&`) would otherwise loop.
     */
    private fun renderType(t: TypeDecl<GlobalTypeId>, harvest: Harvest, depth: Int = 0): String {
        if (depth > 6) return "…"
        return when (t) {
            is TypeDecl.Ref -> {
                // Named TypeAst → use the name. Anonymous → recurse into
                // its body so the user sees `int *` rather than a raw
                // GlobalTypeId. Unresolved (cross-CU dangling Ref) →
                // fall back to the id stringification.
                val ast = harvest.typeAsts[t.id]
                ast?.name ?: ast?.let { renderType(it.body, harvest, depth + 1) } ?: "T_${t.id}"
            }
            is TypeDecl.Pointer -> "${renderType(t.pointee, harvest, depth + 1)} *"
            is TypeDecl.Reference -> "${renderType(t.referent, harvest, depth + 1)} &"
            is TypeDecl.Const -> "${renderType(t.inner, harvest, depth + 1)} const"
            is TypeDecl.Volatile -> "${renderType(t.inner, harvest, depth + 1)} volatile"
            is TypeDecl.Array -> "${renderType(t.element, harvest, depth + 1)}[${t.length ?: ""}]"
            is TypeDecl.Builtin,
            is TypeDecl.Range,
            is TypeDecl.Float,
            is TypeDecl.Complex,
            is TypeDecl.WithSizeAttr,
            -> BuiltinTable.resolve(t)?.name ?: t::class.simpleName?.lowercase() ?: "?"

            is TypeDecl.XRef -> "${kindKeyword(t.kind)} ${t.tagName}"
            is TypeDecl.Struct -> kindKeyword(t.kind)
            is TypeDecl.Enum -> "enum"
            is TypeDecl.FunctionT -> {
                val ret = renderType(t.ret, harvest, depth + 1)
                val params = t.params.joinToString(", ") { renderType(it, harvest, depth + 1) }
                "$ret($params)"
            }

            is TypeDecl.Method -> {
                val cls = renderType(t.cls, harvest, depth + 1)
                val ret = renderType(t.ret, harvest, depth + 1)
                val params = t.params.joinToString(", ") { renderType(it, harvest, depth + 1) }
                "$ret($cls::*)($params)"
            }

            is TypeDecl.InlineDef -> renderType(t.body, harvest, depth + 1)
        }
    }

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
