package ghistabs.render

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.*
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

class Renderer(val index: HarvestIndex, val program: Program, val mode: Mode, val resolver: AddressResolver) :
    Closeable {
    // `also`, not `apply`: inside `apply` the receiver's own (null) `program` property would shadow
    // the constructor param, so openProgram(program) would be handed null.
    val decomp = if (mode != Mode.SKELETON) DecompInterface().also { it.openProgram(program) } else null

    val sources get() = index.sources

    // A function is decompiled once for the whole run, not once per file that renders part of it: with
    // inlined code now placed in the header it came from, one std::string method is wanted by every
    // file that inlines it, and decompilation is ~all of the runtime.
    private val decompiled = mutableMapOf<Address, List<DecompLine>>()

    fun decompile(func: Func): List<DecompLine> = decompiled.getOrPut(func.addr) {
        val ghFunc = program.functionManager.getFunctionAt(func.addr) ?: return@getOrPut emptyList()
        // Folded onto the function's *own* source, not the file asking: that only governs which locals
        // drop out of the head fold, and the head is used only where the function is defined.
        val own = with(index) { func.source() } ?: return@getOrPut emptyList()
        runCatching { decomp?.decompileFunction(ghFunc, 30, TaskMonitor.DUMMY) }
            .getOrNull()?.compressedDecompLines(own, func, mode == Mode.ELIDE_SJLJ).orEmpty()
    }

    fun renderSkeleton(source: String) = RenderContext(this, source).render()

    /**
     * Render every source into [dir], one file per source (named from the source path). Wraps the
     * render in a transaction — it defines terminated strings at undefined pointer targets it meets
     * while rendering constant values. Returns the number of files written; stops early if [monitor]
     * is canceled.
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

private fun Owner.kind() = when (this) {
    Owner.FUNCTION_BODY, Owner.INLINED_BODY -> FragmentKind.DECOMP
    Owner.FUNC_DELIM -> FragmentKind.FUNC_DELIM
    Owner.GLOBAL -> FragmentKind.DECL_GLOBAL
    Owner.LOCAL -> FragmentKind.DECL_LOCAL
    Owner.TYPE_BODY -> FragmentKind.TYPE_BODY
    Owner.TYPEDEF -> FragmentKind.TYPEDEF
    Owner.INCLUDE -> FragmentKind.OTHER
}

private fun safeName(source: String) = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").trim('_')

private class RenderContext(val renderer: Renderer, val source: String) {
    val program get() = renderer.program
    val resolver get() = renderer.resolver

    // [source] and every per-record source field come from the resolver's facade with §15 folds
    // already applied, so comparisons here are fold-to-fold with no per-site work.
    private val index = renderer.index

    private val rawFuncs = index.functionsBySource[source].orEmpty()
    private val lines = index.linesBySource[source].orEmpty()
    private val typeDecls = index.typesBySource[source].orEmpty()
        .filter { it.name != null && it.declLine > 0 }
    private val symbols = index.symbolsBySource[source].orEmpty()

    // Collapse long template spellings (basic_string<char,…> → string) in AST-rendered types,
    // matching the DTM shortening pass that only the decompiler (DTM-backed) otherwise reflects.
    private val shortener by lazy { harvestTemplateShortener(index) }

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

        // One allocation for the whole file. Every pass declares what it wants and writes nothing;
        // the allocator resolves all of it at once, with the full picture. That is what removes the
        // retroactive sweep — contention between a decompiled body and a declaration gcc misfiled
        // into its span is settled by [Owner] priority up front, so there is no losing fragment left
        // over to demote into a `// stray:` comment.
        val claims = buildList {
            // Decomp first: it decides which functions get a body, which is what tells the brace pass
            // whose delimiters are already covered.
            if (renderer.decomp != null) addAll(decompClaims())
            addAll(typedefClaims())
            addAll(localClaims())
            addAll(globalClaims())
            addAll(functionBraceClaims())
            addAll(typeBodyClaims())
            if (renderer.decomp != null) addAll(includeClaims())
        }
        write(allocate(claims, maxLine))
        // Annotations, not content: they carry no code and share a row with whatever holds it, so
        // they are never claims. In decomp mode the body restates them, so they go where it landed.
        emitSlineAnnotations()
        reportAnomalies()
        // Trailing blank/stale lines are trimmed only in decomp mode; skeleton output
        // stays fully source-aligned.
        return canvas.render(trim = renderer.decomp != null) + anonAggregateAppendix() + instantiationAppendix()
    }

    // Anonymous aggregates carry no source line (declLine == null), so they can't be placed inline
    // on the line-based canvas. Append them as a skeleton-only diagnostic block under their synthetic
    // Anon_ id; decomp omits them entirely. Deduped by ghidraName (content-hashed, §20).
    private fun anonAggregateAppendix(): String {
        if (renderer.mode != Mode.SKELETON) return ""
        val anon = renderer.index.anonAggregates[source]

        if (anon.isNullOrEmpty()) return ""
        val blocks = anon.joinToString("\n\n") { ast ->
            when (val body = ast.body) {
                is TypeDecl.Struct -> {
                    val members = body.renderFull(index, program, shortener)
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

    /**
     * Instantiations that shared a declLine with the one rendered inline. Every instantiation of a
     * template carries the *template's* line, so only one can hold that row; the rest would otherwise
     * vanish behind the `N instantiations` count. They differ in exactly the way that matters — the
     * substituted types — so they go here in full rather than being summarised away.
     */
    private val mergedInstantiations = mutableListOf<Type>()

    private fun instantiationAppendix(): String {
        if (mergedInstantiations.isEmpty()) return ""
        val blocks = mergedInstantiations
            .sortedWith(compareBy({ it.declLine }, { it.name }))
            .joinToString("\n") { "/* L${it.declLine} */ ${it.oneLineBody()}" }
        return "\n\n/* ── further template instantiations (sharing a declared line above) ── */\n\n$blocks\n"
    }

    /** A type body on one line — the appendix form, where alignment to a source line is meaningless. */
    private fun Type.oneLineBody(): String = when (val b = body) {
        is TypeDecl.Struct -> {
            // Bases too — they are where the instantiations differ most visibly, and dropping them
            // was the one thing the appendix still lost against the pre-rewrite render.
            val bases = b.bases.takeIf { it.isNotEmpty() }
                ?.joinToString(", ", prefix = " : ") {
                    "${it.access.name.lowercase()} ${it.type.render(index, shortener = shortener)}"
                }
                .orEmpty()
            "${b.kind.cxxKeyword()} ${shortener.shortenedOrNull(name ?: "") ?: name}$bases { " +
                b.renderFull(index, program, shortener).joinToString(" ") + " }; /* ${b.sizeBytes} bytes */"
        }

        is TypeDecl.Enum ->
            "enum $name { ${b.members.joinToString(", ") { (n, v) -> "$n = $v" }} }; /* ${b.members.size} members */"

        else -> "$name;"
    }

    /**
     * Skeleton: one `// L n @ 0xADDR[: code-unit]` annotation per (line, code-unit) group — an
     * address map, which is what that mode is for.
     *
     * Decomp: the same fact said as provenance instead. A header line whose code we did not render
     * here was compiled into somebody else's function, and naming that function is the useful half;
     * the addresses are not. 204 rows carried a raw dump and 176 of them held no code at all, so what
     * a reader met on those rows was an address list where the name of that function was the point.
     */
    private fun emitSlineAnnotations() {
        // Aggregates the addresses of N_SLINEs sharing a (line, codeUnit) into one annotation.
        data class SliceKey(val line: Int, val codeUnit: String)

        val byKey = mutableMapOf<SliceKey, MutableSet<Address>>()
        for ((line, addr) in lines) {
            if (line !in 1..maxLine) continue
            val codeUnit = addr.render(program) ?: ""
            byKey.getOrPut(SliceKey(line, codeUnit)) { sortedSetOf() } += addr
        }
        if (renderer.decomp == null) {
            for ((key, addrs) in byKey) {
                val runs = formatAddrRuns(addrs.toList(), program)
                val note = if (key.codeUnit.isEmpty()) runs else "$runs: ${key.codeUnit}"
                canvas[key.line] += Fragment(indentFor(key.line), note = note, kind = FragmentKind.SLINE)
            }
            return
        }
        // One marker per line naming every function this line's code ended up inside — but only where
        // that function belongs to *another* file. A line of main.cpp compiled into main was not
        // inlined anywhere; Ghidra simply folded it into a neighbouring statement, and saying
        // "inlined into main" inside main is nonsense. Rows the decompilation already occupies say it
        // better than any annotation could.
        val own = rawFuncs.mapTo(mutableSetOf()) { it.addr }
        for ((line, addrs) in lines.filter { it.line in 1..maxLine }.groupBy({ it.line }, { it.addr })) {
            if (canvas[line].fragments.any { it.kind == FragmentKind.DECOMP }) continue
            val fns = addrs
                .mapNotNull { program.functionManager.getFunctionContaining(it) }
                .filterNot { it.entryPoint in own }
                .map { it.getName(true) }
                .distinct()
                .ifEmpty { continue }
            canvas[line] += Fragment(indentFor(line), "/* inlined into ${fns.joinToString(", ")} */")
        }
    }

    private fun typedefClaims(): List<Claim> {
        data class Td(val line: Int, val name: String, val rendered: String)

        val typedefs = typeDecls
            .filter { it.declLine in 1..maxLine && it.body !is TypeDecl.Struct && it.body !is TypeDecl.Enum }
            .mapNotNull { ast ->
                ast.name?.let { Td(ast.declLine, it, ast.body.render(index, shortener = shortener)) }
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
        val claims = typedefs.sortedBy { it.line }.mapNotNull { (line, name, rendered) ->
            val key = name to rendered
            if (!seen.add(key)) {
                null
            } else {
                Claim(
                    Owner.TYPEDEF,
                    line,
                    listOf(Row("typedef $rendered $name;", indentFor(line), note = "")),
                    stale = isStale(line) || key in splayed,
                )
            }
        }
        return claims
    }

    /**
     * Write an [Allocation] onto the canvas. The bridge while the rewrite is mid-flight: passes that
     * have been ported hand their claims to the allocator and their placements here, passes that
     * haven't still write fragments directly. See `docs/design-plans/layout-rewrite.md`.
     */
    private fun write(allocation: Allocation) {
        for ((claim, range, copies) in allocation.placed) {
            val free = range.filter { canvas[it].isEmpty() }.ifEmpty { listOf(range.first) }
            val rows = when {
                // Spare rows: break an over-long condition at its top-level `&&`/`||` so it fills the
                // space instead of running to 300 chars.
                claim.owner == Owner.FUNCTION_BODY && free.size > claim.rows.size ->
                    claim.rows.flatMap { r -> wrapDecompLine(r.text, r.indent).map { (d, t) -> Row(t, d, r.note) } }

                else -> claim.rows
            }
            var prev = -1
            var prevIndent = 0
            for ((row, content) in fitRows(rows, free.first()..free.last())) {
                // An expanding block evicts misattributed fragments from the rows it takes, so a lone
                // stale decl can't force it to fold. Carried over from Canvas.layoutBraceBlock.
                if (claim.fit == Fit.ELASTIC) canvas[row].fragments.removeAll { it.stale }
                // Everything crammed onto one row keeps the indent of the statement that opens it —
                // TargetLine takes the shallowest, which let a trailing `}` drag the row to column 0.
                val indent = if (row == prev) prevIndent else content.indent
                // Identical claims merged; say how many there were rather than silently showing one.
                // Aliased copies (ctor C1/C2, dtor D0/D1/D2) are one declaration emitted N times.
                val note = content.note?.let { if (copies > 1) "$it ×$copies" else it }
                canvas[row] += Fragment(indent, content.text, note, claim.owner.kind(), claim.stale)
                prev = row
                prevIndent = indent
            }
        }
        // A claim that lost its row is recorded, never demoted onto a neighbour. FUNC_DELIM losing to
        // a body is the normal case in decomp mode and not worth reporting.
        for ((claim, reason) in allocation.dropped) {
            if (claim.owner == Owner.FUNC_DELIM) continue
            println("skeleton[$source]: dropped ${claim.owner} at L${claim.line} — $reason: ${claim.rows.first().text}")
        }
    }

    private data class DeclKey(val line: Int, val name: String)

    private val seenDecls = mutableSetOf<DeclKey>()

    // One declaration per (line, name); `this` never renders. Guards every decl pass.
    private fun dedup(line: Int, name: String) =
        line in 1..maxLine && name != "this" && seenDecls.add(DeclKey(line, name))

    // A declLine outside the host function's bracket is a stale-N_SOL signature — flag it.
    private fun localClaims(): List<Claim> {
        val rangeByFunc = spans.ranges.associateBy { it.func }
        val claims = mutableListOf<Claim>()
        for (f in rawFuncs) {
            val span = rangeByFunc[f]?.let { it.startLine..(spans.closeLine(f) ?: it.endLine) }
            fun place(line: Int, name: String, type: TypeDecl<GlobalTypeId>, role: String) {
                if (!dedup(line, name)) return
                claims += Claim(
                    Owner.LOCAL,
                    line,
                    listOf(Row("${type.render(index, shortener = shortener)} $name;", indentFor(line), role)),
                    stale = span == null || line !in span,
                )
            }
            for (p in f.params) {
                if (p.sourceFile != source) continue
                if (p.body !is SymbolDecl.Param) continue
                place(
                    p.declLine,
                    p.body.name,
                    p.body.type,
                    when (p.body.location) {
                        VariableLocation.STACK -> "(param)"
                        VariableLocation.REGISTER -> "(reg param)"
                    },
                )
            }
            for (l in f.locals) {
                if (l.sourceFile != source) continue
                if (l.body !is SymbolDecl.Local) continue
                place(
                    l.declLine,
                    l.body.name,
                    l.body.type,
                    when (l.body.location) {
                        VariableLocation.STACK -> "(stack local)"
                        VariableLocation.REGISTER -> "(reg local)"
                    },
                )
            }
        }
        return claims
    }

    // A global/static: the linker's data at [addr] renders as its initializer — a scalar
    // inline, a multi-element aggregate spread over the blank lines below (the same
    // brace-block layout as a struct body).
    private fun emitGlobal(sym: SymbolDecl.Static<GlobalTypeId>, rec: Symbol): Claim? {
        val scope = sym.scope.comment()
        val role = when (rec.recordType) {
            StabType.N_GSYM if sym.scope == StaticScope.GLOBAL -> "(global)"
            StabType.N_GSYM -> "(weird global $scope)"
            StabType.N_LCSYM -> "(.bss $scope)"
            StabType.N_STSYM -> "(.data $scope)"
            StabType.N_ROSYM -> "(.rodata $scope)"
            else -> "($scope)"
        }
        if (!dedup(rec.declLine, sym.name)) return null
        // N_GSYM has rawValue=0 (linker resolves it from the mangled name) — look it up.
        val addr = when {
            rec.rawValue != 0L -> resolver.buildAddress(rec.rawValue)
            else -> resolver.resolve(sym.name)
        }
        val indent = indentFor(rec.declLine)
        val base = "${sym.type.render(index, shortener = shortener)} ${sym.name}"
        // A string-valued global (pointer-to-string whose slot Ghidra left an untyped
        // scalar, or a char[N] holding an RTTI/string literal) renders as one quoted
        // literal; initializerAt would otherwise miss it or spread a per-byte list.
        val literal = addr?.let {
            when {
                sym.type.isPointer(index) -> program.pointerString(it)
                sym.type.isCharArray(index) -> program.stringLiteralAt(it)
                else -> null
            }
        }
        val parts = literal?.let { listOf(it) } ?: addr?.let { program.initializerAt(it) }
        return when {
            parts == null -> Claim(Owner.GLOBAL, rec.declLine, listOf(Row("$base;", indent, role)))

            parts.size == 1 ->
                Claim(Owner.GLOBAL, rec.declLine, listOf(Row("$base = ${parts[0]};", indent, role)))

            // A multi-element aggregate knows where it starts and not where it ends.
            else -> Claim(
                Owner.GLOBAL,
                rec.declLine,
                braceRows(
                    "$base = {",
                    parts.map {
                        "$it,"
                    },
                    "};",
                    indent,
                    role,
                ),
                Fit.ELASTIC,
            )
        }
    }

    /** `open` / one indented row per item / `close`, the shape both aggregate initializers and type bodies take. */
    private fun braceRows(open: String, items: List<String>, close: String, indent: Int, role: String? = null) =
        listOf(Row(open, indent, role)) + items.map { Row(it, indent + 4) } + Row(close, indent)

    // Attributed by CU (`symbolsByCu`), not `s.sourceFile` — gcc emits no `N_SOL(cu)`
    // before N_GSYM, so `sourceFile` points at the last header visited.
    private fun globalClaims() = symbols.mapNotNull { s -> (s.body as? SymbolDecl.Static)?.let { emitGlobal(it, s) } }

    // Openers at startLine (self-closing decl when single-line), closers at the close line.
    private fun functionBraceClaims(): List<Claim> = buildList {
        for (r in spans.ranges) {
            // A rendered body brings its own signature and its own braces. Emitting these as well
            // lets opener and closer be resolved independently — one keeps its row, the other loses
            // it — and the file stops balancing. Keyed on what [decompClaims] actually bodied, not on
            // what merely decompiles: an aliased copy decompiles fine and is deliberately left to the
            // skeleton's side-by-side decls, and skipping its braces on that basis left its `}`
            // behind with no `{` (xvimage.cpp reached depth -3).
            if (r.func in bodied) continue
            val sig = r.func.sourceSignature(program)
            val name = r.func.demangledName
            val openText = if (r.isSingleLine) "$sig;" else "$sig {"
            val openNote = if (r.isSingleLine) name else "opens $name"
            this += Claim(Owner.FUNC_DELIM, r.startLine, listOf(Row(openText, note = openNote)))
            val closeLine = spans.closeLine(r.func) ?: continue
            if (closeLine !in 1..maxLine) continue
            this += Claim(Owner.FUNC_DELIM, closeLine, listOf(Row("}", note = "closes $name")))
        }
    }

    // Struct/enum bodies spread over the blank lines below the decl; opaque types fall
    // back to a one-line forward decl.
    private fun typeBodyClaims(): List<Claim> {
        val claims = mutableListOf<Claim>()
        // Every instantiation of one template carries the *template's* declLine, so N of them arrive
        // for a line the source declares once. They are not peers competing for space; they are one
        // declaration seen N times. Render the fullest body and say how many there were — the same
        // answer the allocator already gives inlined copies — rather than letting one instantiation's
        // members render under another's opener, which is a class that does not exist.
        val byDecl = typeDecls
            .filter { it.declLine in 1..maxLine && it.name != null }
            .filter { it.body is TypeDecl.Struct || it.body is TypeDecl.Enum }
            .distinctBy { it.declLine to it.name }
            .groupBy { it.declLine to it.name!!.substringBefore('<') }

        for ((key, group) in byDecl.entries.sortedBy { it.key.first }) {
            val (line, _) = key
            // Deterministic pick: the most members, then by name, so the choice can't drift with
            // unrelated type-resolution changes.
            val ast = group.maxWith(compareBy({ it.body.memberCount() }, { it.name })) ?: continue
            mergedInstantiations += group.filterNot { it === ast }
            val name = ast.name ?: continue
            val body = ast.body
            if (body !is TypeDecl.Struct && body !is TypeDecl.Enum) continue
            val instantiations = group.size
            val shortName = shortener.shortenedOrNull(name) ?: name

            // Struct fields/methods are self-terminated statements; enum members carry a
            // trailing comma so the space-join in layoutBraceBlock reads as a member list.
            val members = when (body) {
                is TypeDecl.Struct -> body.renderFull(index, program, shortener)
                is TypeDecl.Enum -> body.members.map { (mn, mv) -> "$mn = $mv," }
            }
            val openText = when (body) {
                is TypeDecl.Struct -> {
                    val bases = body.bases.takeIf { it.isNotEmpty() }
                        ?.joinToString(", ", prefix = " : ") {
                            "${it.access.name.lowercase()} ${it.type.render(index, shortener = shortener)}"
                        }
                        .orEmpty()
                    "${body.kind.cxxKeyword()} $shortName$bases {"
                }

                is TypeDecl.Enum -> "enum $shortName {"
            }
            val extent = when (body) {
                is TypeDecl.Struct -> "${body.sizeBytes} bytes"
                is TypeDecl.Enum -> "${body.members.size} members"
            }
            val sizeNote = "/* $extent" + (if (instantiations > 1) ", $instantiations instantiations" else "") + " */"
            val stale = isStale(line)
            claims += if (members.isNotEmpty()) {
                Claim(
                    Owner.TYPE_BODY,
                    line,
                    braceRows(openText, members, "}; $sizeNote", indentFor(line), ""),
                    Fit.ELASTIC,
                    stale,
                )
            } else {
                val keyword = if (body is TypeDecl.Struct) body.kind.cxxKeyword() else "enum"
                val row = Row("$keyword $shortName; $sizeNote", indentFor(line), "")
                Claim(Owner.TYPE_BODY, line, listOf(row), stale = stale)
            }
        }
        return claims
    }

    /** How many members a body declares — the tiebreak when instantiations of one template differ. */
    private fun TypeDecl<GlobalTypeId>.memberCount() = when (this) {
        is TypeDecl.Struct -> fields.size
        is TypeDecl.Enum -> members.size
        else -> 0
    }

    /**
     * Replace each function's span with its decompilation. A real file-scope global/static owns its
     * line and survives as data; everything the decompilation already shows
     * or that's misattributed is dropped; any other stray (a type decl gcc mis-filed here) is demoted
     * to a `// stray:` comment on the close line — never code, so it can't force a cram. The head
     * (signature + folded decls) sits at the start line; the body groups spread K&R-indented down the
     * span, each tagged with its source line. A single-line function has no span, so it isn't bodied.
     */
    /**
     * Claims for every decompiled statement this file should show — its own functions' bodies, and
     * the code it contributed to other files' functions by being inlined into them.
     *
     * No canvas, no sweep. A body's rows claim their own source lines and lose or win contested ones
     * on [Owner] priority, which is what the retroactive "demote whoever wrote first to `// stray:`"
     * pass was doing by hand.
     */
    /** Functions [decompClaims] actually rendered a body for — which is not every function that
     *  decompiles, since aliased copies are deliberately left to the skeleton's side-by-side decls. */
    private val bodied = mutableSetOf<Func>()

    private fun decompClaims(): List<Claim> = buildList {
        for ((func, startLine) in spans.ranges) {
            val closeLine = spans.closeLine(func) ?: startLine
            if (closeLine < startLine) continue
            // Aliased out-of-line copies (ctor C1/C2, dtor D0/D1/D2) all collapse onto one source
            // line; decompiling each would stack duplicate bodies, so only body a single-line
            // function when it is the sole range on its line.
            if (closeLine == startLine && spans.ranges.count { it.startLine == startLine } > 1) continue
            val cLines = renderer.decompile(func).ifEmpty { continue }
            val head = cLines.firstOrNull() ?: continue
            bodied += func

            // The body may borrow the contiguous blank rows after its span when it outgrows it — the
            // next function or global ends the run — so a dense body breathes instead of piling on.
            val gapEnd = ((closeLine + 1)..maxLine).takeWhile { canvasFree(it) }.lastOrNull() ?: closeLine
            // AFTER, not EXACT: aliased copies (ctor C1/C2, dtor D0/D1/D2) share a start line and
            // decompile to identical heads, so under EXACT the two heads merged into one `{` while
            // their two bodies each kept a `}`. Each copy keeps its own opener and slides if it must.
            this += Claim(
                Owner.FUNCTION_BODY,
                startLine,
                listOf(Row(head.text, note = "L $startLine")),
                anchoring = Anchoring.AFTER,
                limit = gapEnd,
            )
            addAll(claimsFor(regionsOf(func, cLines).dropInlined(), gapEnd))
        }

        // The code this file contributed to *other* files' functions. gcc inlined it from here, so its
        // N_SLINEs name this file and its lines belong on this canvas. A header line is compiled into
        // every call site, so identical copies collapse to one tagged `×N`.
        val inlined = index.functions
            .filter { f -> f !in rawFuncs && f.lineEntries.any { it.source == source } }
            .flatMap { regionsOf(it, renderer.decompile(it)).dropInlined() }
            .filter { it.anchor != null }
            .groupBy { r -> r.anchor to r.lines.map { it.text } }
            .map { (_, copies) -> copies.first().also { it.copies = copies.size } }
            .sortedBy { it.anchor }
            .onEach { it.balance() }
        addAll(claimsFor(inlined, maxLine, Owner.INLINED_BODY))
    }

    /** [regions] as claims, none allowed to slide past [limit]. */
    private fun claimsFor(regions: List<Region>, limit: Int, owner: Owner = Owner.FUNCTION_BODY) = regions.map { r ->
        Claim(
            owner,
            r.anchor,
            r.lines.map { Row(it.text, it.depth, r.label(r.anchor ?: 0).takeIf { _ -> !r.foreign }) },
            Fit.ELASTIC,
            anchoring = Anchoring.AFTER,
            limit = limit,
        )
    }

    /** A row nothing has claimed yet — only meaningful before allocation writes anything. */
    private fun canvasFree(line: Int) = line in 1..maxLine

    /**
     * One inlined region, or the statements of one this-file source line. [file] is the file an inlined
     * region was compiled from, null for code belonging to *this* render's source — which is what makes
     * the split symmetric: the same call answers "what of this function is mine" whether the function is
     * defined here or merely inlines code from here.
     */
    private inner class Region(val file: String?) {
        val lines = mutableListOf<DecompLine>()
        val entries = mutableListOf<LineEntry>()

        /** How many identical copies of this region the binary holds — one per site it was inlined at. */
        var copies = 1
        val foreign get() = file != null

        /** The this-file line the region belongs on. Inlined code has none; it rides its call site. */
        val anchor get() = if (foreign) null else entries.filter { it.source == source }.minOfOrNull { it.line }

        // `header.h L a-b` for an inlined region, `L n` for a this-file line — null when gcc gave the
        // region's addresses no N_SLINE in the file it belongs to, so there is no line to name. A
        // block-bounded region may cover entries from several files; only those from the file it is
        // labelled with bound the range.
        fun labelOrNull(): String? {
            val own = entries.filter { it.source == (file ?: source) }.ifEmpty { return null }
            val lo = own.minOf { it.line }
            val hi = own.maxOf { it.line }
            return file?.substringAfterLast('/')?.plus(" ").orEmpty() + "L $lo" + if (hi > lo) "-$hi" else ""
        }

        fun label(fallback: Int) = (labelOrNull() ?: "L $fallback") + if (copies > 1) " ×$copies" else ""

        /**
         * Close the region's own braces. A region placed in the file it was *inlined from* is a slice
         * of someone else's body, so the block it opens is closed — or the one it closes opened — over
         * in the caller. Standing alone here it has to carry both ends itself.
         */
        fun balance() {
            val delta = lines.sumOf { l -> l.text.count { it == '{' } - l.text.count { it == '}' } }
            val depth = lines.firstOrNull()?.depth ?: 0
            when {
                delta > 0 -> lines += DecompLine("}".repeat(delta), null, depth)
                delta < 0 -> lines.add(0, DecompLine("{".repeat(-delta), null, depth))
            }
        }
    }

    /**
     * [cLines] split into regions by which file each statement came from. Keeps the decompiler's
     * statement order (it inverts conditions and leaves gotos, so its structure isn't the source's).
     *
     * Membership is the N_SLINE's file — the per-address answer, and the complete one; the lexical block
     * only *bounds* a foreign region, which is what N_SLINE can't do: two adjacent inlined calls into
     * the same header are one undivided stretch of entries but two blocks, so keying on the block splits
     * them instead of merging them into one blob. Where gcc bracketed no block, the stretch of same-file
     * entries is the fallback extent.
     *
     * Each foreign region's marker is appended to the row before it rather than taking a row of its own:
     * the code itself now renders in the file it was written in, so all this file needs is the note that
     * something was inlined here.
     */
    private fun regionsOf(func: Func, cLines: List<DecompLine>): List<Region> {
        val slines = func.lineEntries.sortedBy { it.addr.offset }
        fun entryFor(addr: Address?) = addr?.let { a -> slines.lastOrNull { it.addr.offset <= a.offset } }

        val regions = mutableListOf<Region>()
        var currentKey: Any? = null
        for (dl in cLines.drop(1)) {
            val entry = entryFor(dl.address)
            val block = dl.block?.takeIf { it.source != source }
            // An addressless row (a bare brace) belongs to whatever it follows.
            val key = when {
                entry == null -> currentKey
                entry.source != source -> block ?: entry.source
                else -> entry.line
            }
            if (regions.isEmpty() || key != currentKey) {
                regions += Region((block?.source ?: entry?.source)?.takeIf { it != source })
            }
            regions.last().lines += dl
            entry?.let { regions.last().entries += it }
            currentKey = key
        }
        return regions
    }

    /**
     * Inlined statements dropped — they render in the file they were written in — but their braces and
     * their names kept.
     *
     * A decompiled function is one brace-nested body with the inlined statements interleaved into the
     * caller's own, so dropping a region wholesale takes with it the `}` that closed a block this
     * file's code opened: unpackfile.cpp went from 61/61 braces to 15/13 and stopped parsing. Keeping
     * the region's brace-*only* rows doesn't fix it either — those are all closers, an opener riding
     * its statement (`if (x) {`) — which swung it the other way, to 15/59.
     *
     * So each dropped region leaves behind its net brace delta. Nesting depth is a property of the
     * body, not of any one file — gcc gives a brace row no N_SLINE, and the block it closes may have
     * been opened by code from any file the function inlined — so every view can carry it, and every
     * view balances, because the body they were split out of did.
     */
    private fun List<Region>.dropInlined(): List<Region> {
        val kept = mutableListOf<Region>()
        var marks = ""
        var depth = 0

        // Fold what an inlined stretch left behind onto the last row of the statement it followed.
        fun flushOnto(r: Region) {
            if (marks.isEmpty() && depth == 0) return
            val braces = if (depth > 0) "{".repeat(depth) else "}".repeat(-depth)
            val last = r.lines.lastOrNull() ?: return
            val head = listOf(last.text, braces).filter(String::isNotEmpty).joinToString(" ")
            r.lines[r.lines.lastIndex] = last.copy(text = head + marks)
            marks = ""
            depth = 0
        }

        for (r in this) {
            if (r.foreign) {
                // Statements gone — they render in the file they were written in. What is left is the
                // net brace delta, which belongs to no file, and the name, which rides the statement
                // it followed rather than taking a row of its own. As its own claim the marker
                // contended for rows and, outranking declarations, evicted them: a
                // `class iterator_traits<…>` lost its line to an `inlines atomicity.h L 51`. Left
                // anchorless instead it sorted to the end of the file, 200 rows of bare markers.
                depth += r.lines.sumOf { l -> l.text.count { it == '{' } - l.text.count { it == '}' } }
                r.labelOrNull()?.let { marks += " /* ⇐ inlines $it */" }
                continue
            }
            kept += r
            flushOnto(r)
        }
        // A one-line accessor whose body is *all* inlined — Image::size — keeps nothing of its own to
        // fold onto, and its brace delta would be discarded, leaving its head's `{` hanging open.
        if (kept.isEmpty() && (marks.isNotEmpty() || depth != 0)) {
            kept += Region(null).also { it.lines += DecompLine("", null, 0) }
        }
        kept.lastOrNull()?.let { flushOnto(it) }
        return kept
    }

    // The headers this file pulls in, as #include lines in the blank space above the first line of
    // content: the headers whose code got inlined here (non-.cpp N_SLINE sources) plus the headers
    // that *define the types* its functions use — the type each signature/local names, resolved to
    // its definition (an `XRef` forward-decl via its tag, a `Ref`/`InlineDef` via its id) and that
    // type's base classes — so a .cpp that only calls out-of-line (nothing inlined, e.g. appimage.cpp)
    // still declares its dependencies. Placed only within the available top room; overflow stacks on
    // the last free line rather than pushing content down.
    private fun includeClaims(): List<Claim> {
        val referenced = mutableSetOf<Type>()
        fun collect(decl: TypeDecl<GlobalTypeId>) {
            val ast = when (decl) {
                is TypeDecl.Ref -> index.byId(decl.id)
                is TypeDecl.XRef -> index.byXRef(decl, silent = true)
                else -> return decl.children.flatten().forEach { collect(it) }
            }
            if (ast != null && referenced.add(ast)) {
                (ast.body as? TypeDecl.Struct)?.bases?.forEach { collect(it.type) }
            }
        }
        for (f in rawFuncs) {
            collect(f.decl.type)
            for (s in f.params + f.locals) collect(s.body.type)
        }

        val fromTypes = referenced.asSequence().map { index.effectiveSourceFor(it) }
        val fromInlined = rawFuncs.asSequence().flatMap { it.lineEntries.asSequence() }.map { it.source }
        val headers = (fromInlined + fromTypes)
            .filter { it != source && it.hasHeaderExtension() }
            .distinct()
            .sorted()
            .map { "#include \"${it.substringAfterLast('/')}\"" }
            .toList()
        return headers.map { Claim(Owner.INCLUDE, null, listOf(Row(it)), anchoring = Anchoring.BAND) }
    }

    // Diagnostic: a function/type/global landing inside another function's interior is
    // suspect. Deduped; overload sets on the same demangled name are skipped.
    private fun reportAnomalies() {
        val anomalies = sortedSetOf<String>()
        for ((func1, startLine) in spans.ranges) {
            val closeLine = spans.closeLine(func1) ?: continue
            val interior = (startLine + 1) until closeLine
            val name1 = func1.demangledName
            val where = "inside $name1 [L$startLine..L$closeLine]"
            for ((func2, startLine2, endLine) in spans.ranges) {
                if (func2 === func1) continue
                val name2 = func2.demangledName
                if (name2 == name1) continue
                if (startLine2 in interior) {
                    anomalies += "skeleton[$source]: function $name2 opens at L$startLine2 $where"
                }
                if (endLine in interior && startLine2 !in interior) {
                    anomalies += "skeleton[$source]: function $name2 closes at L$endLine $where"
                }
            }
            for (ast in typeDecls) {
                if (ast.declLine !in interior) continue
                anomalies += "skeleton[$source]: type ${ast.name} declared at L${ast.declLine} $where"
            }
            for (s in symbols) {
                if (s.declLine !in interior) continue
                val nm = (s.body as? SymbolDecl.Static)?.name ?: continue
                anomalies += "skeleton[$source]: global/static $nm at L${s.declLine} $where"
            }
        }
        anomalies.forEach(::println)
    }
}
