package ghistabs.render

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.LineEntry
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.harvest.hasHeaderExtension
import ghistabs.importer.AddressResolver
import ghistabs.parse.*
import ghistabs.runTransaction
import java.io.Closeable
import java.io.File

enum class Mode {
    SKELETON,
    DECOMPILE,

    // Elide gcc SjLj exception scaffolding (the __Unwind_SjLj_* calls, personality store, and the
    // per-call-site index writes) from decompilation output. No-op on DWARF-EH (ELF) binaries.
    ELIDE_SJLJ,
}

class Renderer(val typeResolver: TypeResolver, val program: Program, val mode: Mode, val resolver: AddressResolver) :
    Closeable {
    // `also`, not `apply`: inside `apply` the receiver's own (null) `program` property would shadow
    // the constructor param, so openProgram(program) would be handed null.
    val decomp = if (mode != Mode.SKELETON) DecompInterface().also { it.openProgram(program) } else null

    val sources get() = typeResolver.sources

    fun renderSkeleton(source: String) = RenderContext(this, source).render()

    /**
     * Render every source into [dir], one file per source (named from the source path). Wraps the
     * render in a transaction — it defines terminated strings at undefined pointer targets it meets
     * while rendering constant values. Returns the number of files written; stops early if [monitor]
     * is cancelled.
     */
    fun renderAll(dir: File, monitor: TaskMonitor = TaskMonitor.DUMMY): Int {
        monitor.initialize(sources.size.toLong())
        dir.mkdirs()
        return program.runTransaction("stabs-render-all") {
            sources.asSequence().map { source ->
                val out = renderSkeleton(source)
                out.isNotBlank().also { if (it) File(dir, safeName(source)).writeText(out) }
            }.takeWhile { runCatching { monitor.incrementProgress() }.isSuccess }.count()
        }
    }

    // We own the DecompInterface, so terminate its process rather than just detaching the program.
    override fun close() {
        decomp?.dispose()
    }
}

private fun safeName(source: String) = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").trim('_')

private class RenderContext(val renderer: Renderer, val source: String) {
    val harvest get() = renderer.typeResolver.harvest
    val program get() = renderer.program
    val resolver get() = renderer.resolver

    // [source] and every per-record source field come from the resolver's facade with §15 folds
    // already applied, so comparisons here are fold-to-fold with no per-site work.
    private val tr = renderer.typeResolver

    private val rawFuncs = tr.functions.filter { tr.functionSource[it] == source }
    private val lines = tr.linesBySource[source].orEmpty()
    private val typeDecls = harvest.typeAsts.values
        .filter { tr.effectiveSourceFor(it) == source && it.name != null && it.declLine > 0 }
    private val symbols = tr.symbolsBySource[source].orEmpty()

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
        renderer.decomp?.let {
            applyDecompilation(it)
            emitIncludes()
        }
        // Trailing blank/stale lines are trimmed only in decomp mode; skeleton output
        // stays fully source-aligned.
        return canvas.render(trim = renderer.decomp != null) + anonAggregateAppendix()
    }

    // Anonymous aggregates carry no source line (declLine == null), so they can't be placed inline
    // on the line-based canvas. Append them as a skeleton-only diagnostic block under their synthetic
    // Anon_ id; decomp omits them entirely. Deduped by ghidraName (content-hashed, §20).
    private fun anonAggregateAppendix(): String {
        if (renderer.mode != Mode.SKELETON) return ""
        val anon = harvest.typeAsts.values
            .filter { it.name.isNullOrEmpty() && it.body.isXRefTarget && tr.effectiveSourceFor(it) == source }
            .distinctBy { it.ghidraName }
            .sortedBy { it.ghidraName }
        if (anon.isEmpty()) return ""
        val blocks = anon.joinToString("\n\n") { ast ->
            when (val body = ast.body) {
                is TypeDecl.Struct -> {
                    val members = body.renderFull(harvest, program, shortener)
                        .joinToString("\n    ", prefix = "\n    ", postfix = "\n")
                    "${body.kind.cxxKeyword()} ${ast.ghidraName} {$members}; /* ${body.sizeBytes} bytes */"
                }

                is TypeDecl.Enum ->
                    "enum ${ast.ghidraName} { ${body.members.joinToString(", ") { (n, v) -> "$n = $v" }} };" +
                        " /* ${body.members.size} members */"

                else -> ""
            }
        }
        return "\n\n/* ── anonymous aggregates (no source line) ── */\n\n$blocks\n"
    }

    /** One `// L n @ 0xADDR[: code-unit]` annotation per (line, code-unit) group. */
    private fun emitSlineAnnotations() {
        // Aggregates the addresses of N_SLINEs sharing a (line, codeUnit) into one annotation.
        data class SliceKey(val line: Int, val codeUnit: String)

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
        data class Td(val line: Int, val name: String, val rendered: String)

        val typedefs = typeDecls
            .filter { it.declLine in 1..maxLine && it.body !is TypeDecl.Struct && it.body !is TypeDecl.Enum }
            .mapNotNull { ast ->
                ast.name?.let { Td(ast.declLine, it, ast.body.render(harvest, shortener = shortener)) }
            }

        // A genuine typedef has one definition site. The same alias+target recurring across a .cpp
        // is stab N_SOL splaying one libstdc++ instantiation typedef (`iterator_traits<X>::_ValueType`,
        // emitted per instantiation) whose N_SOL named the CU — flag every copy misattributed.
        // Headers are the canonical home and keep theirs.
        val splayed = if (source.hasHeaderExtension()) {
            emptySet()
        } else {
            typedefs.groupBy { it.name to it.rendered }.filterValues { it.size > 1 }.keys
        }

        // Collapse duplicate (name, target) copies to one line. Keying on the pair — not the
        // declLine the old dedup used — is what makes this fire when misattribution splays a
        // typedef across several bogus lines.
        val seen = mutableSetOf<Pair<String, String>>()
        for (td in typedefs.sortedBy { it.line }) {
            val key = td.name to td.rendered
            if (!seen.add(key)) continue
            canvas[td.line] += Fragment(
                indentFor(td.line),
                "typedef ${td.rendered} ${td.name};",
                note = "",
                kind = FragmentKind.TYPEDEF,
                stale = isStale(td.line) || key in splayed,
            )
        }
    }

    private data class DeclKey(val line: Int, val name: String)

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
                s.rawValue != 0L -> resolver.buildAddress(s.rawValue)
                name != null -> resolver.resolve(name)
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
            val sig = r.func.sourceSignature(program)
            val name = r.func.demangledName
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
                note = "closes ${r.func.demangledName}",
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
     * Replace each function's span with its decompilation. A real file-scope global/static owns its
     * line and survives as data; every fragment the decomp already shows ([FragmentKind.subsumedByDecomp])
     * or that's misattributed is dropped; any other stray (a type decl gcc mis-filed here) is demoted
     * to a `// stray:` comment on the close line — never code, so it can't force a cram. The head
     * (signature + folded decls) sits at the start line; the body groups spread K&R-indented down the
     * span, each tagged with its source line. A single-line function has no span, so it isn't bodied.
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
                .getOrNull()?.compressedDecompLines(renderer.mode == Mode.ELIDE_SJLJ) ?: continue
            val head = cLines.firstOrNull() ?: continue

            // Capture each surviving stray with its original line so the demoted comment keeps that
            // line's provenance tag rather than the close line's. A live global stays put as data.
            val strays = mutableListOf<String>()
            for (line in r.startLine..closeLine) {
                canvas[line].fragments.removeAll { f ->
                    when {
                        f.kind == FragmentKind.DECL_GLOBAL && !f.stale -> false

                        f.kind.subsumedByDecomp || f.stale -> true

                        else -> {
                            strays += listOfNotNull(f.code, f.commentAt(line)).joinToString("  ")
                            true
                        }
                    }
                }
            }

            val slines = r.func.lineEntries.sortedBy { it.addr.address.offset }
            fun entryFor(addr: Address?) = addr?.let { a -> slines.lastOrNull { it.addr.address.offset <= a.offset } }
            fun refOf(e: LineEntry): String {
                val file = if (e.source == source) "" else "${e.source.substringAfterLast('/')} "
                return "${file}L ${e.line}"
            }

            // A run of decomp statements on one source line ([entry]), keeping Ghidra's per-line brace
            // formatting so the span's blank room can be filled a line at a time (braces on their own line).
            class DecompRun(val lines: MutableList<DecompLine>, val entry: LineEntry?)

            // Keep the decompiler's statement order (it may invert conditions / leave gotos, so its
            // structure isn't the source's), but gather into one run each contiguous group of
            // statements belonging to one this-file source line: repeats of the line plus inlined-
            // header code (a foreign N_SOL folds into its call site's line). A run keeps Ghidra's
            // per-line brace formatting, so it lays one line each where the span has room.
            val runs = mutableListOf<DecompRun>()
            var currentLine: Int? = null
            for (dl in cLines.drop(1)) {
                val entry = entryFor(dl.address)
                val ownLine = entry?.takeIf { it.source == source }?.line
                if (runs.isNotEmpty() && (ownLine == null || ownLine == currentLine)) {
                    runs.last().lines += dl
                } else {
                    runs += DecompRun(mutableListOf(dl), entry)
                }
                if (ownLine != null) currentLine = ownLine
            }

            canvas[r.startLine] += Fragment(code = head.text, note = "L ${r.startLine}", kind = FragmentKind.DECOMP)
            // Spread the runs down to fill the height; each expands into the blank rows up to the next
            // run — braces on their own lines — or crams where it's too tight. The body stays inside the
            // span when it fits (nothing spills past the close); when it would otherwise cram, borrow the
            // blank rows after the function up to the next one, so it can breathe instead of piling on.
            // When the body would cram, borrow only the *contiguous* blank rows immediately after the
            // span — the next global or function ends the run — so a dense body never smears across
            // every blank line to the end of the file.
            val gapEnd = ((closeLine + 1)..maxLine).takeWhile { canvas[it].isEmpty() }.lastOrNull() ?: closeLine
            val sizes = runs.map { it.lines.size }
            val spanFree = (r.startLine + 1..closeLine).count { canvas[it].isEmpty() }
            val end = if (sizes.sum() <= spanFree) closeLine else gapEnd
            // `spreadBlocks` reserves rows per run size, so a big run (a whole `while` loop coalesced
            // onto one source line) gets its share of the interior blanks instead of cramming onto one
            // row while a small sibling wastes the space around it.
            val targets = spreadBlocks(r.startLine, end, sizes)
            runs.forEachIndexed { i, run ->
                val note = run.entry?.let(::refOf) ?: "L ${targets[i]}"
                placeRun(targets[i], targets.getOrNull(i + 1) ?: (end + 1), run.lines, note)
            }
            for (text in strays) canvas[closeLine] += Fragment(note = text, kind = FragmentKind.STRAY)
        }
    }

    // Lay a run's lines onto the free rows in [start, limit): one per row while there is room (so
    // Ghidra's `{`-ends-the-line / `}`-on-its-own-line survives), the overflow crammed onto the last.
    // A statement row carries the run's source-line tag; a structural row (a bare brace, no
    // instructions → null address) has no stabs source line, so it carries no tag — a synthetic one
    // would just restate its grid position and, on the synthesised close line, read as an off-by-one.
    // Indent is the line's own nesting level.
    private fun placeRun(start: Int, limit: Int, lines: List<DecompLine>, note: String) {
        val free = (start until limit).filter { canvas[it].isEmpty() }.ifEmpty { listOf(start) }
        // With spare rows, break over-long statements at their top-level `&&`/`||` boundaries so a
        // crammed condition fills the blank space instead of one 300-char line; dense runs (no spare
        // rows) place one line per row as-is. A wrapped piece keeps its statement's address; a brace
        // keeps its null one.
        val rows = if (free.size > lines.size) {
            lines.flatMap { dl -> wrapDecompLine(dl.text, dl.depth).map { (d, t) -> Triple(d, t, dl.address) } }
        } else {
            lines.map { Triple(it.depth, it.text, it.address) }
        }
        var prev = -1
        rows.forEachIndexed { i, (depth, text, address) ->
            val line = free[minOf(i, free.lastIndex)]
            val rowNote = note.takeIf { address != null && line != prev }
            canvas[line] += Fragment(depth, text, rowNote, FragmentKind.DECOMP)
            prev = line
        }
    }

    // The headers this file pulls in, as #include lines in the blank space above the first line of
    // content: the headers whose code got inlined here (non-.cpp N_SLINE sources) plus the headers
    // that *define the types* its functions use — the type each signature/local names, resolved to
    // its definition (an `XRef` forward-decl via its tag, a `Ref`/`InlineDef` via its id) and that
    // type's base classes — so a .cpp that only calls out-of-line (nothing inlined, e.g. appimage.cpp)
    // still declares its dependencies. Placed only within the available top room; overflow stacks on
    // the last free line rather than pushing content down.
    private fun emitIncludes() {
        val resolver = renderer.typeResolver
        val referenced = mutableSetOf<TypeAst>()
        fun collect(decl: TypeDecl<GlobalTypeId>) {
            val ast = when (decl) {
                is TypeDecl.Ref -> harvest.typeAsts[decl.id]
                is TypeDecl.XRef -> resolver.byXRef(decl, silent = true)
                is TypeDecl.InlineDef -> return collect(decl.body)
                is TypeDecl.Pointer -> return collect(decl.pointee)
                is TypeDecl.Reference -> return collect(decl.referent)
                is TypeDecl.Const -> return collect(decl.inner)
                is TypeDecl.Volatile -> return collect(decl.inner)
                is TypeDecl.WithSizeAttr -> return collect(decl.inner)
                is TypeDecl.Array -> return collect(decl.element)
                else -> null
            }
            if (ast != null && referenced.add(ast)) {
                (ast.body as? TypeDecl.Struct)?.bases?.forEach { collect(it.type) }
            }
        }
        for (f in rawFuncs) {
            collect(f.decl.type)
            for (s in f.params + f.locals) collect(s.body.type)
        }

        val fromTypes = referenced.asSequence().map { resolver.effectiveSourceFor(it) }
        val fromInlined = rawFuncs.asSequence().flatMap { it.lineEntries.asSequence() }.map { it.source }
        val headers = (fromInlined + fromTypes)
            .filter { it != source && it.hasHeaderExtension() }
            .distinct()
            .sorted()
            .map { "#include \"${it.substringAfterLast('/')}\"" }
            .toList()
        if (headers.isEmpty()) return
        val room = ((1..maxLine).firstOrNull { canvas[it].fragments.isNotEmpty() } ?: (maxLine + 1)) - 1
        if (room <= 0) return
        headers.forEachIndexed { i, include ->
            canvas[(i + 1).coerceAtMost(room)] += Fragment(code = include, kind = FragmentKind.OTHER)
        }
    }

    // Diagnostic: a function/type/global landing inside another function's interior is
    // suspect. Deduped; overload sets on the same demangled name are skipped.
    private fun reportAnomalies() {
        val anomalies = sortedSetOf<String>()
        for (r in spans.ranges) {
            val closeLine = spans.closeLine(r.func) ?: continue
            val interior = (r.startLine + 1) until closeLine
            val fname = r.func.demangledName
            val where = "inside $fname [L${r.startLine}..L$closeLine]"
            for (g in spans.ranges) {
                if (g.func === r.func) continue
                val gname = g.func.demangledName
                if (gname == fname) continue
                if (g.startLine in interior) {
                    anomalies += "skeleton[$source]: function $gname opens at L${g.startLine} $where"
                }
                if (g.endLine in interior && g.startLine !in interior) {
                    anomalies += "skeleton[$source]: function $gname closes at L${g.endLine} $where"
                }
            }
            for (ast in typeDecls) {
                if (ast.declLine !in interior) continue
                anomalies += "skeleton[$source]: type ${ast.name} declared at L${ast.declLine} $where"
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
