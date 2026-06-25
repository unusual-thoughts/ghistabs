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
import ghistabs.harvest.TypeAst
import ghistabs.materialize.BuiltinTable
import ghistabs.parse.*
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
    @ValueSource(strings = ["xapasmcsr.exe", "xmltest", "appquery.exe", "box2d_tests"])
    fun writeSkeletons(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler(if (fixture.extension.lowercase() == "exe") "mingw" else null)
            .log(log).monitor(monitor).load().use { loadResults ->
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

                // Move previous run to `<outDir>.old` (overwriting any earlier .old)
                // so a `diff -r outDir outDir.old` shows what this run changed. Need
                // a clean outDir for the same reason as before — files we no longer
                // attribute anything to would otherwise stick around from the old run.
                val outDir = File("build/test-output/skeletons/${fixture.nameWithoutExtension}")
                if (outDir.exists()) {
                    val oldDir = File("${outDir.path}.old")
                    oldDir.deleteRecursively()
                    outDir.renameTo(oldDir)
                }
                outDir.mkdirs()

                // Attribute each function to the source whose N_SLINE entries
                // cover the most of its address range. This is the
                // authoritative signal (gcc emits N_SOL("header") before
                // template instantiations' N_FUN and resets it before CU
                // functions), so std::pair::pair lands in stl_pair.h and
                // CParser::ParseSymbol lands in parse.cpp. Functions with
                // sizeBytes==0 or no covered N_SLINE drop out of every
                // skeleton — they have no place to go.
                val funcToSource = attributeFunctionsBySource(harvest)
                val lineEntries = harvest.lineEntries
                val typeResolver = ghistabs.harvest.TypeResolver(
                    harvest.typeAsts,
                    harvest.rawCollisions,
                    harvest = harvest,
                )
                val headerHints = typeResolver.multiSourceHeaderHints
                val sources = (
                    lineEntries.keys +
                        funcToSource.values +
                        harvest.typeAsts.values.map { headerHints[it.name] ?: it.id.source.filename }
                    )
                    .filter { it.isNotEmpty() }
                    .toSet()

                var written = 0
                for (source in sources) {
                    val skeleton = renderSkeleton(source, harvest, lineEntries, program, funcToSource, headerHints)
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
            }
    }

    /**
     * Pull the outermost class / namespace name out of an Itanium-ABI
     * mangled symbol — e.g. `_ZN13EquExpressionC1ERKS_` → `EquExpression`,
     * `_ZN7CParser11ParseSymbolEv` → `CParser`. Used to look up the
     * class's `declSourceFile` and pin the function there when N_SLINE
     * would otherwise drag a defaulted/implicit method into whichever
     * header materialised it (e.g. gcc's implicit `EquExpression` copy
     * ctor materialised inside `std::pair<…, EquExpression>` lands at
     * `stl_pair.h:84`; the class itself lives elsewhere).
     *
     * Returns null for non-nested-name mangles (`_Z…` without `N`) and
     * for symbols whose first segment is a substitution-prefix like
     * `St` (std) — we WANT those to keep their N_SLINE attribution.
     */
    private fun outermostClassFrom(mangled: String): String? {
        if (!mangled.startsWith("_ZN")) return null
        var i = 3
        // First segment must be a length-prefixed name (digits).
        if (i >= mangled.length || !mangled[i].isDigit()) return null
        var j = i
        while (j < mangled.length && mangled[j].isDigit()) j++
        val len = mangled.substring(i, j).toIntOrNull() ?: return null
        if (j + len > mangled.length) return null
        return mangled.substring(j, j + len)
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
        // Index TypeAsts by simple name → BINCL-anchored source of the
        // type's defining declaration. Prefer concrete Struct / Enum
        // bodies over forward-decl `XRef`s and over Refs / aliases:
        // gcc emits XRef stubs for class names mentioned via pointer
        // /reference inside unrelated headers (e.g. `class
        // CSymLexStream;` reachable from `<iostream>` via the include
        // graph), and those XRef stubs share the class's simple name
        // — picking one of them would route the class's methods to
        // `<iostream>` instead of `lexstream.h`.
        val classSourceByName = mutableMapOf<String, String>()
        fun bodyRank(body: TypeDecl<GlobalTypeId>) = when (body) {
            is TypeDecl.Struct, is TypeDecl.Enum -> 2
            is TypeDecl.XRef -> 0
            else -> 1
        }

        val bestRank = mutableMapOf<String, Int>()
        for (ast in harvest.typeAsts.values) {
            val n = ast.name ?: continue
            val rank = bodyRank(ast.body)
            if (rank > (bestRank[n] ?: -1)) {
                bestRank[n] = rank
                classSourceByName[n] = ast.id.source.filename
            }
        }

        val out = mutableMapOf<OpenFunction, String>()
        for (f in harvest.openFunctions) {
            if (isSyntheticInit(f)) {
                out[f] = f.cu.filename
                continue
            }
            // Trust SLINE attribution first: the source whose N_SLINE covers the
            // earliest address in the function's range is where gcc says the body
            // lives. Only fall back to the class-declaration source when SLINE
            // names nothing (defaulted/implicit methods gcc materialises inside an
            // unrelated template header, e.g. EquExpression's implicit copy ctor
            // emitted inside std::pair<…, EquExpression>).
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
            if (bestSrc != null) {
                out[f] = bestSrc
                continue
            }
            outermostClassFrom(f.name)?.let { classSourceByName[it] }?.let { out[f] = it }
        }
        return out
    }

    private fun renderSkeleton(
        source: String,
        harvest: Harvest,
        lineEntries: Map<String, List<LineEntry>>,
        program: Program,
        funcToSource: Map<OpenFunction, String>,
        headerHints: Map<String, String>,
    ): String {
        // Resolve each ast's effective source via the hint: a multi-CU class with a
        // header majority among its member-function SLINEs lands at the header, not
        // at whichever .cpp gcc happened to emit the body burst in.
        fun TypeAst.effectiveSource(): String = name?.let { headerHints[it] } ?: id.source.filename

        val rawFuncs = harvest.openFunctions.filter { funcToSource[it] == source }
        val lines = lineEntries[source].orEmpty()
        val hasTypeDecls = harvest.typeAsts.values.any {
            it.effectiveSource() == source && it.name != null && it.declLine > 0
        }
        if (rawFuncs.isEmpty() && lines.isEmpty() && !hasTypeDecls) return ""

        data class FuncRange(val func: OpenFunction, val startLine: Int, val endLine: Int)

        val rawRanges = rawFuncs.mapNotNull { f ->
            val lo = f.addr.address.offset
            val hi = lo + f.sizeBytes
            // Prefer SLINE entries already attributed to `source`. When there are none
            // and this isn't a gcc synthetic init wrapper (whose body genuinely lives
            // at the static's decl line in some unrelated header, so any "line in CU"
            // we'd compute is meaningless), fall back to any SLINE in the function's
            // address range — that's the case for out-of-line copies of header-declared
            // methods, whose SLINEs went to the .cpp where the body was instantiated.
            val inside = lines.filter { it.addr.address.offset in lo until hi }
                .ifEmpty {
                    if (isSyntheticInit(f)) {
                        emptyList()
                    } else {
                        lineEntries.values.asSequence().flatten()
                            .filter { it.addr.address.offset in lo until hi }
                            .toList()
                    }
                }
            if (inside.isEmpty()) return@mapNotNull null
            // Anchor start/end on address-order, not line-number-order: the lowest-address
            // N_SLINE is the prologue (function's actual source line); the highest-address
            // N_SLINE is the epilogue. Picking min/max line number gets pulled around by
            // inlined-template references.
            val sortedByAddr = inside.sortedBy { it.addr.address.offset }
            val start = sortedByAddr.first().line
            val end = sortedByAddr.last().line
            FuncRange(f, start, end)
        }.sortedBy { it.startLine }
        // Drop ranges strictly contained inside another's range in this source — those
        // are method-declaration fragments in a header where another method's range
        // happens to span the same lines (gcc emits SLINE for headers with sparse,
        // out-of-order line attribution).
        val ranges = rawRanges.filter { r ->
            rawRanges.none { other ->
                other !== r &&
                    other.startLine <= r.startLine &&
                    r.endLine <= other.endLine &&
                    (other.startLine < r.startLine || r.endLine < other.endLine)
            }
        }
        val funcs = ranges.map { it.func }

        // A single-line range is rendered as a self-closing declaration on its one line
        // — there's no body to bracket. gcc emits this shape both for header-declared
        // inline methods' out-of-line copies (whose body collapses to the inline decl)
        // and for synthetic wrappers (`_GLOBAL__I_*`, `__static_initialization_…`)
        // whose body has no source-step structure. Multi-line ranges close on
        // endLine+1, or endLine when that collides with a sibling's open.
        fun isSingleLine(r: FuncRange) = r.startLine == r.endLine

        val startLines = ranges.map { it.startLine }.toSet()
        val closeLineByFunc = ranges.mapNotNull { r ->
            when {
                isSingleLine(r) -> null
                (r.endLine + 1) in startLines -> r.func to r.endLine
                else -> r.func to r.endLine + 1
            }
        }.toMap()

        val maxLine = sequenceOf(
            closeLineByFunc.values.maxOrNull() ?: 0,
            lines.maxOfOrNull { it.line } ?: 0,
            ranges.maxOfOrNull { it.startLine } ?: 0,
            ranges.maxOfOrNull { it.endLine } ?: 0,
            harvest.typeAsts.values
                .filter { it.effectiveSource() == source && it.declLine > 0 && it.name != null }
                .maxOfOrNull { it.declLine } ?: 0,
            harvest.symbolsByCu[source]?.maxOfOrNull { it.declLine } ?: 0,
        ).max()
        if (maxLine == 0) return ""

        // Layout: one bucket per source line; render exactly maxLine
        // output lines (blank where empty) so source line N == output
        // line N.
        val buckets = Array(maxLine + 1) { mutableListOf<String>() }

        val funcSpan = ranges.map { (f, start, _) ->
            val close = closeLineByFunc[f] ?: start
            start..close
        }

        fun inFunction(line: Int) = funcSpan.any { line in it }

        // Group N_SLINE entries by (line, codeUnit) and aggregate addresses, so e.g. six
        // ~MarkerInst PUSH-EBP instances at L 63 collapse to one comment listing all addresses.
        data class SliceKey(val line: Int, val codeUnit: String)

        val sliceAddrs = mutableMapOf<SliceKey, MutableSet<Address>>()
        for (entry in lines) {
            if (entry.line !in 1..maxLine) continue
            val codeUnit = describeAddress(program, entry.addr.address) ?: ""
            sliceAddrs.getOrPut(SliceKey(entry.line, codeUnit)) { sortedSetOf() } +=
                entry.addr.address
        }
        for ((key, addrs) in sliceAddrs) {
            val lineTag = "L" + key.line.toString().padStart(4)
            val indent = if (inFunction(key.line)) "    " else ""
            val addrList = formatAddrRuns(addrs.toList(), program)
            val suffix = if (key.codeUnit.isEmpty()) "" else ": ${key.codeUnit}"
            buckets[key.line] += "$indent// $lineTag @ $addrList$suffix"
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

        // declLine past the file's own activity is a stale-N_SOL flag: gcc emitted the
        // typedef inside this CU's stab burst but the line number refers to the last
        // header N_SOL pointed at. We still render, but mark the warning. For files
        // with body activity (CUs) we trust the body's extent — anything past it is
        // suspect. For files with no body activity (pure headers like Keywords.h),
        // we take typeAsts as the activity signal — the file legitimately has only
        // type declarations.
        val bodyExtent = sequenceOf(
            lines.maxOfOrNull { it.line } ?: 0,
            harvest.symbolsByCu[source]?.maxOfOrNull { it.declLine } ?: 0,
            ranges.maxOfOrNull { it.endLine } ?: 0,
        ).max()
        val activityExtent = if (bodyExtent > 0) {
            bodyExtent
        } else {
            harvest.typeAsts.values
                .filter { it.effectiveSource() == source && it.declLine > 0 && it.name != null }
                .maxOfOrNull { it.declLine } ?: 0
        }
        val seenTypeDecls = mutableSetOf<TypeDeclKey>()
        // BINCL-anchored source for type attribution. Typedefs render as one-liners here;
        // Struct/Enum/Union/Class run in a post-pass below so they can expand into blank lines.
        for (ast in harvest.typeAsts.values
            .filter { it.effectiveSource() == source && it.declLine in 1..maxLine && it.name != null }
            .sortedBy { it.declLine }) {
            val line = ast.declLine
            val name = ast.name ?: continue
            val body = ast.body
            if (body is TypeDecl.Struct || body is TypeDecl.Enum) continue
            val key = TypeDeclKey(line, name, body::class.simpleName ?: "")
            if (!seenTypeDecls.add(key)) continue
            val tag = if (line > activityExtent) "${lineTag(line)} stale N_SOL?" else lineTag(line)
            buckets[line] += "${indentFor(line)}typedef ${renderType(body, harvest)} $name;  $tag"
        }

        // Param + local + global declarations — N_PSYM / N_RSYM /
        // N_GSYM / N_LCSYM / N_STSYM `desc`. Dedupe per (line, name)
        // because the same template instantiated many times produces
        // duplicate `__val` / `__first` entries at the same header line.
        // `this` is filtered — no signal in seeing it 12× per line.
        data class DeclKey(val line: Int, val name: String)

        val seenDecls = mutableSetOf<DeclKey>()
        fun emitDecl(
            line: Int,
            name: String,
            type: TypeDecl<GlobalTypeId>,
            suffix: String,
            initFromAddr: Address? = null,
        ) {
            if (line !in 1..maxLine) return
            if (name == "this") return
            if (!seenDecls.add(DeclKey(line, name))) return
            val init = initFromAddr?.let { initializerAt(program, it) }
            val rendered = if (init != null) {
                "${renderType(type, harvest)} $name = $init;"
            } else {
                "${renderType(type, harvest)} $name;"
            }
            buckets[line] += "${indentFor(line)}$rendered  ${lineTag(line)} $suffix"
        }
        // Render params/locals of every function pinned to this source. When the
        // declLine falls outside the host function's bracket, it's gcc's stale-N_SOL
        // signature: the local was emitted inside the host function's stab burst but
        // the line number refers to whichever file N_SOL was last set to (typically
        // an STL header where the inlined method was declared). Mark the suffix so
        // the reader knows the line number isn't meaningful for this source.
        val rangeByFunc = ranges.associateBy { it.func }
        for (f in rawFuncs) {
            val span = rangeByFunc[f]?.let { it.startLine..(closeLineByFunc[f] ?: it.endLine) }
            fun suffixFor(declLine: Int, base: String): String =
                if (span != null && declLine in span) base else "$base; stale N_SOL?"
            for (p in f.params) {
                if (p.sourceFile != source) continue
                when (val d = p.body) {
                    is SymbolDecl.StackParam -> emitDecl(p.declLine, d.name, d.type, suffixFor(p.declLine, "(param)"))
                    is SymbolDecl.RegParam -> emitDecl(p.declLine, d.name, d.type, suffixFor(p.declLine, "(reg param)"))
                    else -> {}
                }
            }
            for (l in f.locals) {
                if (l.sourceFile != source) continue
                when (val d = l.body) {
                    is SymbolDecl.RegLocal -> emitDecl(l.declLine, d.name, d.type, suffixFor(l.declLine, "(reg local)"))
                    is SymbolDecl.StackLocal -> emitDecl(
                        l.declLine,
                        d.name,
                        d.type,
                        suffixFor(l.declLine, "(stack local)"),
                    )
                    else -> {}
                }
            }
        }
        // For globals/statics, attribute by CU rather than by
        // `s.sourceFile`. gcc doesn't emit `N_SOL("xapasmcsr.cpp")`
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
                // N_LCSYM/N_STSYM carry the variable's address in rawValue. N_GSYM has
                // rawValue=0 — the linker resolves the address from the mangled symbol
                // name, so look it up in Ghidra's symbol table.
                val name = (s.body as? SymbolDecl.Global)?.name
                    ?: (s.body as? SymbolDecl.StaticVar)?.name
                val addr = when {
                    s.rawValue != 0L -> program.addressFactory.defaultAddressSpace.getAddress(s.rawValue)
                    name != null -> program.symbolTable.getSymbols(name).firstOrNull()?.address
                    else -> null
                }
                when (val d = s.body) {
                    is SymbolDecl.Global -> emitDecl(s.declLine, d.name, d.type, suffix, addr)
                    is SymbolDecl.StaticVar -> emitDecl(s.declLine, d.name, d.type, suffix, addr)
                    else -> {}
                }
            }
        }

        // Function openers at startLine. Tag with the source line so
        // alignment drift after edits is immediately obvious. Skip
        // single-line ranges — see closeLineByFunc above.
        for (r in ranges) {
            val (f, startLine, _) = r
            val sig = ghidraSignatureFor(f, program)
            val lineTag = "L" + startLine.toString().padStart(4)
            val opener = if (isSingleLine(r)) {
                "$sig;  /* $lineTag — ${f.decl.name} */"
            } else {
                "$sig {  /* $lineTag — opens ${f.decl.name} */"
            }
            buckets[startLine].add(0, opener)
        }
        // Function closers at chosen close line.
        for ((f, _, _) in ranges) {
            val closeLine = closeLineByFunc[f] ?: continue
            if (closeLine !in 1..maxLine) continue
            val lineTag = "L" + closeLine.toString().padStart(4)
            buckets[closeLine] += "}  /* $lineTag — closes ${demangledNameOf(f)} */"
        }

        // Post-pass: Struct / Enum bodies. Expand into consecutive blank lines below the
        // decl line when there's room; otherwise fall back to a one-line forward decl.
        data class TypeBodyKey(val line: Int, val name: String)

        val seenTypeBodies = mutableSetOf<TypeBodyKey>()
        for (ast in harvest.typeAsts.values
            .filter { it.effectiveSource() == source && it.declLine in 1..maxLine && it.name != null }
            .sortedBy { it.declLine }) {
            val line = ast.declLine
            val name = ast.name ?: continue
            val body = ast.body
            if (body !is TypeDecl.Struct && body !is TypeDecl.Enum) continue
            if (!seenTypeBodies.add(TypeBodyKey(line, name))) continue

            val memberLines = when (body) {
                is TypeDecl.Struct -> renderStructMembers(body, harvest, program)
                is TypeDecl.Enum -> body.members.map { (mn, mv) -> "    $mn = $mv," }
                else -> emptyList()
            }
            val indent = indentFor(line)
            val openLine = when (body) {
                is TypeDecl.Struct -> {
                    val bases = if (body.bases.isEmpty()) {
                        ""
                    } else {
                        " : " + body.bases.joinToString(", ") {
                            "${it.access.name.lowercase()} ${renderType(it.type, harvest)}"
                        }
                    }
                    "${aggKeyword(body)} $name$bases {"
                }

                is TypeDecl.Enum -> "enum $name {"

                else -> error("unreachable")
            }
            val sizeNote = when (body) {
                is TypeDecl.Struct -> "/* ${body.sizeBytes} bytes */"
                is TypeDecl.Enum -> "/* ${body.members.size} members */"
                else -> ""
            }

            // Count consecutive blank buckets below `line`. Need at least
            // memberLines.size + 1 (for closing brace) to expand.
            var available = 0
            var probe = line + 1
            while (probe <= maxLine && buckets[probe].isEmpty()) {
                available++
                probe++
            }
            val tag = if (line > activityExtent) "${lineTag(line)} stale N_SOL?" else lineTag(line)
            if (memberLines.isNotEmpty() && available >= memberLines.size + 1) {
                buckets[line] += "$indent$openLine  $tag"
                for ((i, m) in memberLines.withIndex()) {
                    buckets[line + 1 + i] += "$indent$m"
                }
                val closeIdx = line + 1 + memberLines.size
                buckets[closeIdx] += "$indent}; $sizeNote".trimEnd()
            } else if (memberLines.isNotEmpty()) {
                // Not enough blank room for one-member-per-line — compact form on one line.
                val compactMembers = memberLines.joinToString(" ") { it.trimStart() }
                buckets[line] += "$indent$openLine $compactMembers }; $sizeNote  $tag"
            } else {
                // No members (opaque) — forward decl.
                val keyword = when (body) {
                    is TypeDecl.Struct -> aggKeyword(body)
                    is TypeDecl.Enum -> "enum"
                    else -> "struct"
                }
                buckets[line] += "$indent$keyword $name; $sizeNote  $tag"
            }
        }

        // Diagnostic: anything that lands inside another function's interior is
        // suspicious — gcc shouldn't be emitting a nested function, a top-level
        // type definition, or a global at a line claimed by an enclosing N_FUN
        // range. Dedup before printing: D1/D2 dtor variants and template
        // instantiations otherwise repeat each observation N times. Skip
        // self-comparisons on demangled name (overload set hitting same line).
        val anomalies = sortedSetOf<String>()
        for ((f, startLine, _) in ranges) {
            val closeLine = closeLineByFunc[f] ?: continue
            val interior = (startLine + 1) until closeLine
            val fname = demangledNameOf(f)
            for ((g, gStart, gEnd) in ranges) {
                if (g === f) continue
                val gname = demangledNameOf(g)
                if (gname == fname) continue
                if (gStart in interior) {
                    anomalies +=
                        "skeleton[$source]: function $gname opens at L$gStart inside $fname [L$startLine..L$closeLine]"
                }
                if (gEnd in interior && gStart !in interior) {
                    anomalies +=
                        "skeleton[$source]: function $gname closes at L$gEnd inside $fname [L$startLine..L$closeLine]"
                }
            }
            for (ast in harvest.typeAsts.values) {
                if (ast.id.source.filename != source) continue
                if (ast.declLine !in interior) continue
                val name = ast.name ?: continue
                anomalies +=
                    "skeleton[$source]: type $name declared at L${ast.declLine} inside $fname [L$startLine..L$closeLine]"
            }
            for ((cu, syms) in harvest.symbolsByCu) {
                if (cu != source) continue
                for (s in syms) {
                    if (s.declLine !in interior) continue
                    val nm = (s.body as? SymbolDecl.Global)?.name
                        ?: (s.body as? SymbolDecl.StaticVar)?.name
                        ?: continue
                    anomalies +=
                        "skeleton[$source]: global/static $nm at L${s.declLine} inside $fname [L$startLine..L$closeLine]"
                }
            }
        }
        anomalies.forEach(::println)

        // Strict alignment: source line N → output line N. Multiple bucket items
        // share one output line, joined together.
        return buildString {
            for (line in 1..maxLine) {
                val bucket = buckets[line]
                if (bucket.isNotEmpty()) append(bucket.joinToString("   "))
                append('\n')
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
    private fun describeAddress(program: Program, addr: Address): String? =
        when (val cu = program.listing.getCodeUnitAt(addr)) {
            is Instruction -> program.functionManager.getFunctionContaining(addr)?.getName(true)
                ?: program.symbolTable.getPrimarySymbol(addr)
                    ?.takeIf { it.source != SourceType.DEFAULT }
                    ?.getName(true)

            is Data -> {
                val sym = program.symbolTable.getPrimarySymbol(addr)
                    ?.takeIf { it.source != SourceType.DEFAULT }
                    ?.getName(true)
                val value = runCatching { cu.value?.toString() }.getOrNull()
                val type = cu.dataType.name
                val body = listOfNotNull(type, value).joinToString(" = ")
                if (sym != null) "$sym → $body" else body
            }

            else -> null
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

    // gcc 3.x stabs emit `s` for both `struct` and `class`; promote to "class" when
    // any method or base carries non-public access, OR when there are any methods
    // at all (plain C structs have none — the presence of methods means C++).
    private fun aggKeyword(s: TypeDecl.Struct<GlobalTypeId>): String {
        if (s.kind == AggrKind.STRUCT &&
            (
                s.methods.isNotEmpty() ||
                    s.bases.any { it.access != Access.PUBLIC }
                )
        ) {
            return "class"
        }
        return kindKeyword(s.kind)
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

    /**
     * Format a set of addresses as `0xS-0xE` interval(s) where consecutive entries cover
     * back-to-back code units (instruction.length apart), so e.g. the prologue's 5 N_SLINEs
     * at `0x401000..0x40100f` render as `0x401000-0x40100f` instead of a comma list.
     */
    private fun formatAddrRuns(addrs: List<Address>, program: Program): String {
        if (addrs.isEmpty()) return ""
        val sorted = addrs.sortedBy { it.offset }
        val runs = mutableListOf<Pair<Address, Address>>()
        var runStart = sorted[0]
        var runEnd = sorted[0]
        for (i in 1 until sorted.size) {
            val cur = sorted[i]
            val inst = program.listing.getInstructionAt(runEnd)
            val expectedNext = inst?.next?.address
                ?: program.listing.getCodeUnitAt(runEnd)?.takeIf {
                    it.length > 0
                }?.let { runEnd.add(it.length.toLong()) }
            if (expectedNext != null && cur == expectedNext) {
                runEnd = cur
            } else {
                runs += runStart to runEnd
                runStart = cur
                runEnd = cur
            }
        }
        runs += runStart to runEnd
        fun hex(a: Address) = "0x" + a.offset.toString(16).padStart(8, '0')
        return runs.joinToString(", ") { (s, e) -> if (s == e) hex(s) else "${hex(s)}-${hex(e)}" }
    }

    /** Render a Struct's body members for in-skeleton expansion: one C-style decl per line. */
    private fun renderStructMembers(
        body: TypeDecl.Struct<GlobalTypeId>,
        harvest: Harvest,
        program: Program,
    ): List<String> {
        val fieldLines = body.fields
            .filter { !it.isStatic }
            .sortedBy { it.offsetBits }
            .map { f ->
                val type = renderType(f.type, harvest)
                "    $type ${f.name};  /* +${f.offsetBits / 8}B */"
            }
        val funcByMangled = harvest.openFunctions.associateBy { it.name }
        val methodLines = body.methods.mapNotNull { m ->
            val mangled = m.mangled ?: return@mapNotNull null
            val func = funcByMangled[mangled] ?: return@mapNotNull null
            "    ${ghidraSignatureFor(func, program)};"
        }
        return fieldLines + methodLines
    }

    /**
     * Function signature via Ghidra's API at the function's entry address — Ghidra has
     * already resolved calling convention, parameter names and types from analysis +
     * imported stabs types, so the rendered signature reflects what the binary actually
     * does (not the demangler's textual guess).
     */
    private fun ghidraSignatureFor(f: OpenFunction, program: Program): String {
        val func = program.functionManager.getFunctionAt(f.addr.address) ?: return f.name
        return func.signature.prototypeString
    }

    /**
     * Initializer string for a global/static at [addr] via Ghidra's data API. Primitives
     * render their value (TRUE/FALSE, ints, strings); pointers dereference one level so
     * a `char const *` pointing at a string shows the literal. Structs expand their
     * components into a brace-list. Returns null when the value is uninformative
     * (uninitialized `??`, empty struct, or zero-length).
     */
    private fun initializerAt(program: Program, addr: Address): String? {
        val cu = program.listing.getDataAt(addr) ?: return null
        val target = (cu.value as? Address)?.let { program.listing.getDataAt(it) }
        val pick = target ?: cu
        // byte/char arrays render as hex-list by default; recover the string literal
        // by reading bytes directly.
        if (pick.numComponents > 0 && pick.dataType is ghidra.program.model.data.Array) {
            val arr = pick.dataType as ghidra.program.model.data.Array
            if (arr.elementLength == 1) {
                val bytes = ByteArray(pick.length)
                runCatching { program.memory.getBytes(pick.address, bytes) }.getOrNull()
                    ?: return null
                val end = bytes.indexOf(0).let { if (it == -1) bytes.size else it }
                if ((0 until end).all {
                        val b = bytes[it].toInt() and 0xff
                        b in 0x20..0x7e
                    }
                ) {
                    return "\"${String(bytes, 0, end, Charsets.US_ASCII)}\""
                }
            }
        }
        // Try Ghidra's own representation first — for typed strings it returns a
        // string literal; for primitives the value; for many structs the field list.
        val repr = runCatching { pick.defaultValueRepresentation }.getOrNull()
        if (!repr.isNullOrEmpty() && repr != "??" && !repr.contains("Empty-Structure")) {
            return repr
        }
        // Fallback for structs Ghidra rendered as `<Empty-Structure>` (no inline value
        // for the whole record) — recurse into components, picking up pointer
        // dereferences (RTTI structs whose interesting content is one pointer away).
        if (pick.numComponents > 0) {
            val parts = (0 until pick.numComponents).mapNotNull { i ->
                val c = pick.getComponent(i) ?: return@mapNotNull null
                val v = (c.value as? Address)?.let { program.listing.getDataAt(it) }
                    ?.runCatching { defaultValueRepresentation }?.getOrNull()
                    ?: runCatching { c.defaultValueRepresentation }.getOrNull()
                v?.takeIf { it.isNotEmpty() && it != "??" && !it.contains("Empty-Structure") }
            }
            if (parts.isNotEmpty()) return "{ ${parts.joinToString(", ")} }"
        }
        return null
    }

    private fun demangledNameOf(f: OpenFunction): String {
        val mangled = f.decl.name
        val demangled = runCatching {
            @Suppress("DEPRECATION")
            ghidra.app.util.demangler.DemanglerUtil.demangle(mangled)
        }.getOrNull() ?: return mangled
        return demangled.demangledName ?: demangled.name ?: mangled
    }
}
