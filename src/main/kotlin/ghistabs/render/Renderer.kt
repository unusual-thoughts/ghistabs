package ghistabs.render

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.LineEntry
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl

// Aggregates the addresses of N_SLINEs sharing a (line, codeUnit) into one annotation.
private data class SliceKey(val line: Int, val codeUnit: String)

// Dedup keys: templates instantiated many times repeat the same alias / `__val` / `__first`
// at one header line.
private data class TypeDeclKey(val line: Int, val name: String, val bodyKind: String)

private data class DeclKey(val line: Int, val name: String)

class Renderer(val typeResolver: TypeResolver, val program: Program, val decomp: DecompInterface? = null) {
    fun renderSkeleton(source: String) = RenderContext(this, source).render()
}

private class RenderContext(val renderer: Renderer, val source: String) {
    val harvest get() = renderer.typeResolver.harvest
    val program get() = renderer.program

    // A multi-CU class lands at the header its member SLINEs mostly point to, not the
    // .cpp gcc emitted the body burst in.
    private fun TypeAst.effectiveSource() =
        name?.let { renderer.typeResolver.multiSourceHeaderHints[it] } ?: id.source.filename

    private val rawFuncs = harvest.openFunctions.filter { renderer.typeResolver.functionSource[it] == source }
    private val lines = harvest.lineEntries[source].orEmpty()
    private val typeDecls = harvest.typeAsts.values
        .filter { it.effectiveSource() == source && it.name != null && it.declLine > 0 }
    private val symbols = harvest.symbolsByCu[source].orEmpty()

    // Collapse long template spellings (basic_string<char,…> → string) in AST-rendered types,
    // matching the DTM shortening pass that only the decompiler (DTM-backed) otherwise reflects.
    private val shortener by lazy { harvestTemplateShortener(harvest) }

    private val spans = FunctionSpans.of(rawFuncs, source)

    private val maxLine = sequenceOf(
        spans.maxLine,
        lines.maxOfOrNull { it.line } ?: 0,
        typeDecls.maxOfOrNull { it.declLine } ?: 0,
        symbols.maxOfOrNull { it.declLine } ?: 0,
    ).max()

    private val canvas = Canvas(maxLine)

    private fun indentFor(line: Int) = if (spans.inFunction(line)) 4 else 0

    // A declLine past the file's activity extent flags a stale N_SOL. Body extent for CUs;
    // type-decl extent for pure-header files.
    private val activityExtent = sequenceOf(
        lines.maxOfOrNull { it.line } ?: 0,
        symbols.maxOfOrNull { it.declLine } ?: 0,
        spans.ranges.maxOfOrNull { it.endLine } ?: 0,
    ).max().takeIf { it > 0 } ?: (typeDecls.maxOfOrNull { it.declLine } ?: 0)

    // A decl at this line is misattributed (stale N_SOL) if it sits past the file's activity.
    private fun isStale(line: Int) = line > activityExtent

    fun render(): String {
        if (rawFuncs.isEmpty() && lines.isEmpty() && typeDecls.isEmpty()) return ""
        if (maxLine == 0) return ""

        emitSlineAnnotations()
        emitTypedefs()
        emitParamsAndLocals()
        emitGlobals()
        emitFunctionBraces()
        emitTypeBodies()
        reportAnomalies()
        renderer.decomp?.let(::applyDecompilation)
        // Trailing blank/stale lines are trimmed only in decomp mode; skeleton output
        // stays fully source-aligned.
        return canvas.render(trim = renderer.decomp != null)
    }

    /** One `// L n @ 0xADDR[: code-unit]` annotation per (line, code-unit) group. */
    private fun emitSlineAnnotations() {
        val byKey = mutableMapOf<SliceKey, MutableSet<Address>>()
        for (entry in lines) {
            if (entry.line !in 1..maxLine) continue
            val codeUnit = entry.addr.address.render(program) ?: ""
            byKey.getOrPut(SliceKey(entry.line, codeUnit)) { sortedSetOf() } += entry.addr.address
        }
        for ((key, addrs) in byKey) {
            val runs = formatAddrRuns(addrs.toList(), program)
            val note = if (key.codeUnit.isEmpty()) runs else "$runs: ${key.codeUnit}"
            canvas[key.line] += Fragment(indentFor(key.line), note = note, kind = FragmentKind.SLINE)
        }
    }

    private fun emitTypedefs() {
        val seen = mutableSetOf<TypeDeclKey>()
        for (ast in typeDecls.filter { it.declLine in 1..maxLine }.sortedBy { it.declLine }) {
            val name = ast.name ?: continue
            val body = ast.body
            if (body is TypeDecl.Struct || body is TypeDecl.Enum) continue
            if (!seen.add(TypeDeclKey(ast.declLine, name, body::class.simpleName ?: ""))) continue
            canvas[ast.declLine] += Fragment(
                indentFor(ast.declLine),
                "typedef ${body.render(harvest, shortener = shortener)} $name;",
                note = "",
                kind = FragmentKind.TYPEDEF,
                stale = isStale(ast.declLine),
            )
        }
    }

    private val seenDecls = mutableSetOf<DeclKey>()

    // One declaration per (line, name); `this` never renders. Guards every decl pass.
    private fun dedup(line: Int, name: String) =
        line in 1..maxLine && name != "this" && seenDecls.add(DeclKey(line, name))

    // A declLine outside the host function's bracket is a stale-N_SOL signature — flag it.
    private fun emitParamsAndLocals() {
        val rangeByFunc = spans.ranges.associateBy { it.func }
        for (f in rawFuncs) {
            val span = rangeByFunc[f]?.let { it.startLine..(spans.closeLine(f) ?: it.endLine) }
            fun place(line: Int, name: String, type: TypeDecl<GlobalTypeId>, role: String) {
                if (!dedup(line, name)) return
                val stale = span == null || line !in span
                canvas[line] +=
                    Fragment(
                        indentFor(line),
                        "${type.render(harvest, shortener = shortener)} $name;",
                        role,
                        FragmentKind.DECL_LOCAL,
                        stale,
                    )
            }
            for (p in f.params) {
                if (p.sourceFile != source) continue
                when (val d = p.body) {
                    is SymbolDecl.StackParam -> place(p.declLine, d.name, d.type, "(param)")
                    is SymbolDecl.RegParam -> place(p.declLine, d.name, d.type, "(reg param)")
                    else -> {}
                }
            }
            for (l in f.locals) {
                if (l.sourceFile != source) continue
                when (val d = l.body) {
                    is SymbolDecl.RegLocal -> place(l.declLine, d.name, d.type, "(reg local)")
                    is SymbolDecl.StackLocal -> place(l.declLine, d.name, d.type, "(stack local)")
                    else -> {}
                }
            }
        }
    }

    // A global/static: the linker's data at [addr] renders as its initializer — a scalar
    // inline, a multi-element aggregate spread over the blank lines below (the same
    // brace-block layout as a struct body).
    private fun emitGlobal(line: Int, name: String, type: TypeDecl<GlobalTypeId>, role: String, addr: Address?) {
        if (!dedup(line, name)) return
        val indent = indentFor(line)
        val base = "${type.render(harvest, shortener = shortener)} $name"
        // A string-valued global (pointer-to-string whose slot Ghidra left an untyped
        // scalar, or a char[N] holding an RTTI/string literal) renders as one quoted
        // literal; initializerAt would otherwise miss it or spread a per-byte list.
        val literal = addr?.let {
            when {
                type.isPointer(harvest) -> program.pointerString(it)
                type.isCharArray(harvest) -> program.stringLiteralAt(it)
                else -> null
            }
        }
        val parts = literal?.let { listOf(it) } ?: addr?.let { program.initializerAt(it) }
        when {
            parts == null -> canvas[line] += Fragment(indent, "$base;", role, FragmentKind.DECL_GLOBAL)
            parts.size == 1 -> canvas[line] += Fragment(indent, "$base = ${parts[0]};", role, FragmentKind.DECL_GLOBAL)
            else -> canvas.layoutBraceBlock(
                line,
                Fragment(indent, "$base = {", role, FragmentKind.DECL_GLOBAL),
                parts.map { "$it," },
                "};",
            )
        }
    }

    // Attributed by CU (`symbolsByCu`), not `s.sourceFile` — gcc emits no `N_SOL(cu)`
    // before N_GSYM, so `sourceFile` points at the last header visited.
    private fun emitGlobals() {
        for (s in symbols) {
            val role = when (s.recordType) {
                StabType.N_GSYM -> "(global)"
                StabType.N_LCSYM -> "(.bss static)"
                StabType.N_STSYM -> "(.data static)"
                StabType.N_ROSYM -> "(.rodata static)"
                else -> "(symbol)"
            }
            // N_GSYM has rawValue=0 (linker resolves it from the mangled name) — look it up.
            val name = (s.body as? SymbolDecl.Global)?.name ?: (s.body as? SymbolDecl.StaticVar)?.name
            val addr = when {
                s.rawValue != 0L -> program.addressFactory.defaultAddressSpace.getAddress(s.rawValue)
                name != null -> program.symbolTable.getSymbols(name).firstOrNull()?.address
                else -> null
            }
            when (val d = s.body) {
                is SymbolDecl.Global -> emitGlobal(s.declLine, d.name, d.type, role, addr)
                is SymbolDecl.StaticVar -> emitGlobal(s.declLine, d.name, d.type, role, addr)
                else -> {}
            }
        }
    }

    // Openers at startLine (self-closing decl when single-line), closers at the close line.
    private fun emitFunctionBraces() {
        for (r in spans.ranges) {
            val sig = r.func.signature(program)
            val name = r.func.demangledName(program)
            val openText = if (r.isSingleLine) "$sig;" else "$sig {"
            val openNote = if (r.isSingleLine) name else "opens $name"
            canvas[r.startLine].fragments.add(
                0,
                Fragment(code = openText, note = openNote, kind = FragmentKind.FUNC_DELIM),
            )

            val closeLine = spans.closeLine(r.func) ?: continue
            if (closeLine !in 1..maxLine) continue
            canvas[closeLine] += Fragment(
                code = "}",
                note = "closes ${r.func.demangledName(program)}",
                kind = FragmentKind.FUNC_DELIM,
            )
        }
    }

    // Struct/enum bodies spread over the blank lines below the decl; opaque types fall
    // back to a one-line forward decl.
    private fun emitTypeBodies() {
        val seen = mutableSetOf<Pair<Int, String>>()
        for (ast in typeDecls.filter { it.declLine in 1..maxLine }.sortedBy { it.declLine }) {
            val line = ast.declLine
            val name = ast.name ?: continue
            val body = ast.body
            if (body !is TypeDecl.Struct && body !is TypeDecl.Enum) continue
            if (!seen.add(line to name)) continue
            val shortName = shortener.shortenedOrNull(name) ?: name

            // Struct fields/methods are self-terminated statements; enum members carry a
            // trailing comma so the space-join in layoutBraceBlock reads as a member list.
            val members = when (body) {
                is TypeDecl.Struct -> body.renderFull(harvest, program, shortener)
                is TypeDecl.Enum -> body.members.map { (mn, mv) -> "$mn = $mv," }
            }
            val openText = when (body) {
                is TypeDecl.Struct -> {
                    val bases = body.bases.takeIf { it.isNotEmpty() }
                        ?.joinToString(", ", prefix = " : ") {
                            "${it.access.name.lowercase()} ${it.type.render(harvest, shortener = shortener)}"
                        }
                        .orEmpty()
                    "${body.kind.cxxKeyword()} $shortName$bases {"
                }
                is TypeDecl.Enum -> "enum $shortName {"
            }
            val sizeNote = when (body) {
                is TypeDecl.Struct -> "/* ${body.sizeBytes} bytes */"
                is TypeDecl.Enum -> "/* ${body.members.size} members */"
            }
            val stale = isStale(line)
            if (members.isNotEmpty()) {
                val open = Fragment(indentFor(line), openText, "", FragmentKind.TYPE_BODY, stale)
                canvas.layoutBraceBlock(line, open, members, "}; $sizeNote")
            } else {
                val keyword = if (body is TypeDecl.Struct) body.kind.cxxKeyword() else "enum"
                canvas[line] +=
                    Fragment(indentFor(line), "$keyword $shortName; $sizeNote", "", FragmentKind.TYPE_BODY, stale)
            }
        }
    }

    /**
     * Replace each function's span with its decompilation. A fragment in the span is
     * dropped when the decomp already shows it ([FragmentKind.subsumedByDecomp]) or when
     * it's misattributed; every other stray (a type decl / global gcc mis-filed here) is
     * demoted to a `// stray:` comment on the close line — never code, so it can't force
     * a cram. Decomp longer than the span crams its own overflow onto the last line. A
     * single-line function (self-closing decl in the skeleton) has no close line of its
     * own, so its whole body crams onto its one decl line.
     */
    private fun applyDecompilation(decomp: DecompInterface) {
        // Where a decl shares a line with real content, the misattributed one is noise.
        for (b in canvas.multiFragmentLines()) b.fragments.removeAll { it.stale }
        for (r in spans.ranges) {
            val closeLine = spans.closeLine(r.func) ?: r.startLine
            if (closeLine < r.startLine) continue
            // Aliased out-of-line copies (ctor C1/C2, dtor D0/D1/D2) all collapse onto one
            // source line; decompiling each would stack duplicate bodies, so leave those as
            // the skeleton's side-by-side decls and only body a single-line function alone.
            if (closeLine == r.startLine && spans.ranges.count { it.startLine == r.startLine } > 1) continue
            val ghFunc = program.functionManager.getFunctionAt(r.func.addr.address) ?: continue
            val cLines = runCatching { decomp.decompileFunction(ghFunc, 30, TaskMonitor.DUMMY) }
                .getOrNull()?.compressedDecompLines() ?: continue

            // Capture each surviving stray with its original line so the demoted comment
            // keeps that line's provenance tag rather than the close line's.
            val strays = mutableListOf<String>()
            for (line in r.startLine..closeLine) {
                canvas[line].fragments.removeAll { f ->
                    if (!f.kind.subsumedByDecomp && !f.stale) {
                        strays += listOfNotNull(f.code, f.commentAt(line)).joinToString("  ")
                    }
                    true
                }
            }
            // Keep the decompiler's statement order (it may invert conditions / leave gotos, so its
            // structure isn't the source's), but coalesce onto one output line each run of statements
            // that belongs to one source line: repeats of the same line, plus inlined-header code
            // (a foreign N_SOL — the inlined call belongs to its call site's line). This cuts the
            // body to roughly the number of this-file source lines it touches, so it fits the span
            // instead of cramming onto the close line. The folded head (index 0) is never a target.
            val slines = r.func.lineEntries.sortedBy { it.addr.address.offset }
            fun entryFor(addr: Address?) = addr?.let { a -> slines.lastOrNull { it.addr.address.offset <= a.offset } }
            fun refOf(e: LineEntry?): String? {
                e ?: return null
                val file = if (e.source == source) "" else "${e.source.substringAfterLast('/')} "
                return "${file}L ${e.line}"
            }
            val placed = mutableListOf<Pair<StringBuilder, LineEntry?>>()
            var currentLine: Int? = null
            for ((idx, dl) in cLines.withIndex()) {
                val entry = entryFor(dl.address)
                val ownLine = entry?.takeIf { it.source == source }?.line
                if (idx > 0 && placed.size > 1 && (ownLine == null || ownLine == currentLine)) {
                    placed.last().first.append(' ').append(dl.text.trim())
                } else {
                    placed += StringBuilder(dl.text) to entry
                }
                if (ownLine != null) currentLine = ownLine
            }
            val available = closeLine - r.startLine + 1
            if (placed.size <= available) {
                placed.forEachIndexed { i, (text, entry) ->
                    canvas[r.startLine + i] += Fragment(
                        code = text.toString(),
                        note = refOf(entry),
                        kind = FragmentKind.DECOMP,
                    )
                }
            } else {
                for (i in 0 until available - 1) {
                    canvas[r.startLine + i] +=
                        Fragment(
                            code = placed[i].first.toString(),
                            note = refOf(placed[i].second),
                            kind = FragmentKind.DECOMP,
                        )
                }
                val rest = placed.subList(available - 1, placed.size)
                    .map { it.first.toString().trim().trimEnd(';') }
                    .filter { it.isNotEmpty() }
                canvas[closeLine] += Fragment(code = rest.joinToString("; ") + ";", kind = FragmentKind.DECOMP)
            }
            for (text in strays) canvas[closeLine] += Fragment(note = text, kind = FragmentKind.STRAY)
        }
    }

    // Diagnostic: a function/type/global landing inside another function's interior is
    // suspect. Deduped; overload sets on the same demangled name are skipped.
    private fun reportAnomalies() {
        val anomalies = sortedSetOf<String>()
        for (r in spans.ranges) {
            val closeLine = spans.closeLine(r.func) ?: continue
            val interior = (r.startLine + 1) until closeLine
            val fname = r.func.demangledName(program)
            val where = "inside $fname [L${r.startLine}..L$closeLine]"
            for (g in spans.ranges) {
                if (g.func === r.func) continue
                val gname = g.func.demangledName(program)
                if (gname == fname) continue
                if (g.startLine in interior) {
                    anomalies += "skeleton[$source]: function $gname opens at L${g.startLine} $where"
                }
                if (g.endLine in interior && g.startLine !in interior) {
                    anomalies += "skeleton[$source]: function $gname closes at L${g.endLine} $where"
                }
            }
            for (ast in harvest.typeAsts.values) {
                if (ast.id.source.filename != source || ast.declLine !in interior) continue
                val name = ast.name ?: continue
                anomalies += "skeleton[$source]: type $name declared at L${ast.declLine} $where"
            }
            for (s in symbols) {
                if (s.declLine !in interior) continue
                val nm = (s.body as? SymbolDecl.Global)?.name ?: (s.body as? SymbolDecl.StaticVar)?.name ?: continue
                anomalies += "skeleton[$source]: global/static $nm at L${s.declLine} $where"
            }
        }
        anomalies.forEach(::println)
    }
}
