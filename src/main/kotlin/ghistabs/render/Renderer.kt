package ghistabs.render

import ghidra.app.decompiler.ClangToken
import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions.Companion.stabsTypedefsShortened
import ghistabs.baseStackParamOffset
import ghistabs.harvest.*
import ghistabs.importer.AddressResolver
import ghistabs.materialize.TemplateNameShortener
import ghistabs.parse.*
import ghistabs.runTransaction
import java.io.Closeable
import java.io.File
import java.util.IdentityHashMap

enum class Mode {
    SKELETON,
    DECOMPILE,

    // Elide gcc SjLj exception scaffolding (the __Unwind_SjLj_* calls, personality store, and the
    // per-call-site index writes) from decompilation output. No-op on DWARF-EH (ELF) binaries.
    ELIDE_SJLJ,
}

class Renderer(
    val index: HarvestIndex,
    val program: Program,
    val mode: Mode,
    val resolver: AddressResolver,
    // Off for a render meant to be compiled or diffed against real source, where a trailing block of
    // declarations that have no line is noise.
    val showDisplaced: Boolean = true,
    // Annotate each local with the storage gcc gave it. Off by default: it is a property of the
    // compiled code, not of the source being reconstructed.
    val showStorage: Boolean = false,
) : Closeable {
    /**
     * Collapses long template spellings (`basic_string<char,…>` → `string`) across *everything* the
     * render emits, declarations and decompiled code alike. Shortening only the AST half is what left
     * `ofstream os;` next to `basic_ofstream<char,std::char_traits<char>> os;` in one merged head.
     *
     * Not a render setting: it follows the import's, because the two halves come from different places
     * and only agree when they agree with each other. Shortened at import means the datatypes were
     * renamed, so the decompiler already hands us short names and substituting is a no-op the AST side
     * needs; not shortened means long names in the decompiler, which the AST side must then match.
     */
    val shortener by lazy {
        if (program.stabsTypedefsShortened) harvestTemplateShortener(index) else TemplateNameShortener(emptyMap())
    }

    // `also`, not `apply`: inside `apply` the receiver's own (null) `program` property would shadow
    // the constructor param, so openProgram(program) would be handed null.
    val decomp = if (mode != Mode.SKELETON) DecompInterface().also { it.openProgram(program) } else null

    val sources get() = index.sources

    // A function is decompiled once for the whole run, not once per file that renders part of it: with
    // inlined code now placed in the header it came from, one std::string method is wanted by every
    // file that inlines it, and decompilation is ~all of the runtime.
    private val decompiled = mutableMapOf<Address, Decompiled>()

    /** One function's decompilation: the rows the render places, and the dataflow behind them. */
    class Decompiled(val lines: List<DecompLine>, val flow: VarFlow)

    fun decompile(func: Func) = decompiled.getOrPut(func.addr) {
        val results = program.functionManager.getFunctionAt(func.addr)?.let { ghFunc ->
            runCatching { decomp?.decompileFunction(ghFunc, 30, TaskMonitor.DUMMY) }.getOrNull()
        }
        // Folded onto the function's *own* source, not the file asking: that only governs which locals
        // drop out of the head fold, and the head is used only where the function is defined.
        val lines = with(index) { func.source() }?.let { own ->
            // Same address→line lookup [Region] membership uses, narrowed to the function's own
            // source: two branches are only in source order against one file's line numbering.
            val slines = func.lineEntries.filter { it.source == own }.sortedBy { it.addr }
            results?.compressedDecompLines(own, func, ::spell, mode == Mode.ELIDE_SJLJ)
                // Before the render splits it into regions: swapping branches moves their anchors,
                // and the anchors are what every later pass places by.
                ?.uninvertConditions { line -> line.address?.let { a -> slines.lastOrNull { it.addr <= a }?.line } }
        }
        Decompiled(lines.orEmpty(), results?.varFlow() ?: VarFlow(emptyMap(), emptyMap()))
    }

    /**
     * How a decompiler token is spelled in the render: its type name shortened to whatever typedef
     * the import installed, and the `~` Ghidra puts inside a vtable-pointer's name — `PTR_~runtime
     * _error_0043ecfc` — respelled, `~` not being an identifier character (12 of unpackfile's 39
     * remaining structural errors).
     *
     * Per token rather than over the assembled row. A row's offsets then index its final text, and
     * the `~` rule sees one name at a time: a destructor call (`p->~string()`) puts its `~` at the
     * start of its own token and a bitwise not is an operator token, so neither can be caught by a
     * rule about what precedes the `~` in the row.
     */
    fun spell(token: ClangToken): String = spelled.getOrPut(token) {
        shortener.substitute(token.text).let { if ('~' in it) it.respellTilde() else it }
    }

    // Each row asks for its tokens' spellings several times over (once to size the row, once per
    // offset, once for the text) and the substitution is a regex sweep.
    private val spelled = IdentityHashMap<ClangToken, String>()

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

/**
 * A name's every `~` that sits *inside* it, respelled `dtor_`. A name opening with one is a real
 * destructor (`~string`) and keeps it; one in the middle is Ghidra having named a vtable pointer
 * after the destructor it holds, and `~` is not an identifier character there.
 */
private fun String.respellTilde() = buildString {
    this@respellTilde.forEachIndexed { i, c ->
        val inside = c == '~' &&
            i > 0 &&
            this@respellTilde[i - 1].isIdentifierChar() &&
            this@respellTilde.getOrNull(i + 1)?.let { it.isLetter() || it == '_' } == true
        if (inside) append("dtor_") else append(c)
    }
}

private fun Char.isIdentifierChar() = isLetterOrDigit() || this == '_'

private val NON_IDENTIFIER = Regex("[^A-Za-z0-9]+")

/** Consecutive runs sharing a [key] — `groupBy` would merge runs that aren't adjacent. */
private fun <T, K> List<T>.chunkedBy(key: (T) -> K): List<List<T>> =
    fold(mutableListOf<MutableList<T>>()) { acc, item ->
        acc.lastOrNull()?.takeIf { key(it.first()) == key(item) }?.add(item) ?: acc.add(mutableListOf(item))
        acc
    }

/**
 * Where gcc put this local, as an address the decompiler indexes storage by: the register itself, or
 * the frame slot at Ghidra's origin rather than gcc's frame-pointer-relative one. Null for anything
 * that is neither — and for the dbx register numbers [dbxRegisterName] declines to map (the x87
 * stack), which is the same set the importer skips.
 */
private fun Symbol.storageAddress(program: Program): Address? = when ((body as? SymbolDecl.Local)?.location) {
    VariableLocation.REGISTER ->
        dbxRegisterName(program.defaultPointerSize, rawValue.toInt())?.let { program.getRegister(it)?.address }

    VariableLocation.STACK ->
        program.addressFactory.stackSpace.getAddress(rawValue - program.baseStackParamOffset)

    else -> null
}

// An already-closed empty block at the end of a decompiled line — Ghidra spells it `{ }` or `{}`.
private val EMPTY_BLOCK = listOf('{', '}')

/**
 * `template<> ` in front of a declaration whose subject [name] carries template arguments, because
 * that is what such a declaration is: `class fpos<int> { … };` is not legal C++, `template<> class
 * fpos<int> { … };` is. gcc's stabs describe instantiations and never the primary template, so every
 * templated name the render declares is a specialisation.
 *
 * This does not make the render compile — the primary template is still nowhere, so clang moves from
 * "expected unqualified-id" to "explicit specialization of undeclared template class", which is the
 * missing-declaration family a per-file view cannot escape. It is the correct spelling of what the
 * stabs actually say, not a way to quiet the checker.
 */
private fun String.asSpecialization(name: String?) =
    if (name != null && '<' in name && !name.startsWith("operator")) "template<> $this" else this

// The unqualified spelling of a type name, which is what its constructor and destructor are called:
// `std::vector<int>::vector`, not `std::vector<int>::std::vector<int>`.
private fun String.simpleTypeName() = substringBefore('<').substringAfterLast("::")

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

    private val shortener get() = renderer.shortener

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

    /**
     * How far into this file gcc showed evidence of real activity. Past it, a declaration's line is
     * not to be trusted.
     *
     * What counts depends on whether the file *defines* functions, and conflating the two breaks the
     * signal in opposite directions. A .cpp is measured by its code: its own type declarations must
     * not extend it, because misattributed libstdc++ declarations landing at line 898 of a 180-line
     * file are exactly what this is meant to catch — count them and the extent is defined by the very
     * thing it is judging, and `typedef struct bit_vector bit_vector;` at L720 stops being flagged.
     * A header defines no functions and contributes N_SLINEs only where its code was inlined
     * elsewhere, so measuring it that way read xvimage.h's extent off whatever happened to be inlined
     * — it stopped at 32 and called the file's own `class XVImage` at 36 misattributed. There, type
     * declarations are the evidence.
     */
    private val activityExtent = sequenceOf(
        lines.maxOfOrNull { it.line } ?: 0,
        symbols.maxOfOrNull { it.declLine } ?: 0,
        spans.ranges.maxOfOrNull { it.endInclusive } ?: 0,
        if (spans.ranges.isEmpty()) typeDecls.maxOfOrNull { it.declLine } ?: 0 else 0,
    ).max()

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
        // A misattributed claim is not laid out at all. Its line is the one thing about it known to be
        // wrong, so rendering it there — flagged, but in place — spent the file's real estate on a lie:
        // unpackfile.cpp is ~180 lines and was 977 rows because gcc filed libstdc++ down to L898 in it.
        // Surveyed across three programs before removing them: every misattributed row is a Win32
        // typedef in crt1.c, a libgcc internal in cygwin.asm (a *.asm* file, 1060 rows of C locals), or
        // libstdc++ in unpackfile.cpp. tinyxml's and cryptopp's own sources have none at all. Project
        // types appear only as arguments to std templates, which belong to the header, not the .cpp.
        val (misattributed, placeable) = claims.partition { it.stale }
        displaced += misattributed.map { Dropped(it, MISATTRIBUTED) }
        write(allocate(placeable, maxLine))
        // Annotations, not content: they carry no code and share a row with whatever holds it, so
        // they are never claims. In decomp mode the body restates them, so they go where it landed.
        emitSlineAnnotations()
        reportAnomalies()
        // Trailing blank/stale lines are trimmed only in decomp mode; skeleton output
        // stays fully source-aligned.
        val rendered = canvas.render(trim = renderer.decomp != null)
        spans.closeAnomalies(rendered.lines()).forEach { println("skeleton[$source]: $it") }
        return rendered + anonAggregateAppendix() + instantiationAppendix() + displacedAppendix()
    }

    private val displaced = mutableListOf<Dropped>()

    /**
     * Declarations that lost their source line. Losing the row is the right call — a declaration
     * rendered two rows off its line is a lie about where gcc put it — but until now losing it also
     * meant leaving the file, so `class vector<unsigned char…>` at filesystemimage.h L167 simply
     * stopped existing the moment the enclosing body claimed that row. The declaration is real; only
     * its position is unavailable, so it goes here with the line it wanted and why it didn't get it.
     */
    private fun displacedAppendix(): String {
        if (displaced.isEmpty() || !renderer.showDisplaced) return ""
        val rows = displaced
            .sortedWith(compareBy({ it.claim.line ?: Int.MAX_VALUE }, { it.claim.rows.first().text }))
            .joinToString("\n") { (claim, reason) ->
                "${claim.rows.joinToString(" ") { it.text }}  // L ${claim.line} ($reason)"
            }
        return "\n\n/* ── displaced declarations (line unusable) ── */\n\n$rows\n"
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
                    val members = body.renderFull(index, program, shortener, ast.ghidraName.simpleTypeName())
                        .joinToString("\n    ", prefix = "\n    ", postfix = "\n")
                    "${body.kind.cxxKeyword()} ${ast.ghidraName} {$members}; /* ${body.sizeBytes} bytes */"
                        .asSpecialization(ast.ghidraName)
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
        val (bodied, opaque) = mergedInstantiations
            .sortedWith(compareBy({ it.declLine }, { it.name }))
            .partition { it.body.memberCount() > 0 }
        // An instantiation with no members says nothing as `class X<…> {  }; /* 1 bytes */`, and 55 of
        // 68 appendix rows were exactly that. Its *name* is still the point — which specialisations
        // exist, which the `×N` count on the declaring line cannot say — so they list one line per
        // source line instead of one block each.
        val blocks = (
            bodied.map { "/* L${it.declLine} */ ${it.oneLineBody()}" } +
                opaque.groupBy { it.declLine }.map { (line, group) ->
                    "/* L$line */ " + group.mapNotNull { it.name }
                        .joinToString(", ") { shortener.shortenedOrNull(it) ?: it } + ";"
                }
            ).sorted().joinToString("\n").ifEmpty { return "" }
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
            ("${b.kind.cxxKeyword()} ${shortener.shortenedOrNull(name ?: "") ?: name}$bases { ")
                .asSpecialization(shortener.shortenedOrNull(name ?: "") ?: name) +
                b.renderFull(index, program, shortener, name?.simpleTypeName()).joinToString(" ") +
                " }; /* ${b.sizeBytes} bytes */"
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
                    claim.rows.flatMap { r ->
                        wrapDecompLine(r.text, r.indent, r.cuts).map { (d, t) -> Row(t, d, r.note) }
                    }

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
        for (drop in allocation.dropped) {
            if (drop.claim.owner == Owner.FUNC_DELIM) continue
            displaced += drop
            println(
                "skeleton[$source]: dropped ${drop.claim.owner} at L${drop.claim.line} — " +
                    "${drop.reason}: ${drop.claim.rows.first().text}",
            )
        }
    }

    private data class DeclKey(val line: Int, val name: String)

    private val seenDecls = mutableSetOf<DeclKey>()

    // One declaration per (line, name); `this` never renders. Guards every decl pass.
    private fun dedup(line: Int, name: String) =
        line in 1..maxLine && name != "this" && seenDecls.add(DeclKey(line, name))

    private fun varsOf(f: Func): List<Var> = (f.params + f.locals).filter { it.sourceFile == source }.mapNotNull {
        it.renderVar(index, program, shortener, renderer.showStorage)
    }

    private fun localClaims(): List<Claim> {
        val rangeByFunc = spans.ranges.associateBy { it.func }
        // A bodied function declares its variables in the body's folded head, where [decompClaims]
        // merges them. Claiming a row here too duplicated every one Ghidra had also recovered, and the
        // rest lost the contested row to the body and left the file entirely.
        return rawFuncs.filterNot { it in bodied }.flatMap { f ->
            val span = with(spans) { rangeByFunc[f]?.span }
            varsOf(f).filter { dedup(it.line, it.name) }.map {
                Claim(
                    Owner.LOCAL,
                    it.line,
                    listOf(Row(it.text, indentFor(it.line), it.role)),
                    stale = span == null || it.line !in span,
                )
            }
        }
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
        val base = sym.type.renderDecl(sym.name, index, shortener)
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
            this += Claim(Owner.FUNC_DELIM, r.start, listOf(Row(openText, note = openNote)))
            val closeLine = with(spans) { r.closeLine } ?: continue
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
            val ast = group.maxWithOrNull(compareBy({ it.body.memberCount() }, { it.name })) ?: continue
            mergedInstantiations += group.filterNot { it === ast }
            val name = ast.name ?: continue
            val body = ast.body
            if (body !is TypeDecl.Struct && body !is TypeDecl.Enum) continue
            val instantiations = group.size
            val shortName = shortener.shortenedOrNull(name) ?: name

            // Struct fields/methods are self-terminated statements; enum members carry a
            // trailing comma so the space-join in layoutBraceBlock reads as a member list.
            val members = when (body) {
                is TypeDecl.Struct -> body.renderFull(index, program, shortener, name.simpleTypeName())
                is TypeDecl.Enum -> body.members.map { (mn, mv) -> "$mn = $mv," }
            }
            val openText = when (body) {
                is TypeDecl.Struct -> {
                    val bases = body.bases.takeIf { it.isNotEmpty() }
                        ?.joinToString(", ", prefix = " : ") {
                            "${it.access.name.lowercase()} ${it.type.render(index, shortener = shortener)}"
                        }
                        .orEmpty()
                    "${body.kind.cxxKeyword()} $shortName$bases {".asSpecialization(shortName)
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

    /** Functions [decompClaims] actually rendered a body for — which is not every function that
     *  decompiles, since aliased copies are deliberately left to the skeleton's side-by-side decls. */
    private val bodied = mutableSetOf<Func>()

    /**
     * Claims for every decompiled statement this file should show — its own functions' bodies, and
     * the code it contributed to other files' functions by being inlined into them.
     *
     * No canvas, no sweep. A body's rows claim their own source lines and lose or win contested ones
     * on [Owner] priority, which is what the retroactive "demote whoever wrote first to `// stray:`"
     * pass was doing by hand.
     */
    private fun decompClaims(): List<Claim> = buildList {
        // Aliased out-of-line copies — ctor C1/C2, dtor D0/D1/D2 — are one function gcc emitted
        // several times, at *different* addresses, all mapped to one source line. Decompiling each
        // stacked the duplicates: every constructor in xvimage.cpp appeared twice, opening brace and
        // all. The skeleton merges them already, into `opens XVImage ×2`.
        //
        // Keyed on the head — the full signature — at a shared start line, which is the signal the
        // old single-line guard was already built on. Not on the whole body: the copies are decompiled
        // separately, so Ghidra numbers their locals independently and two of xvimage.cpp's three
        // constructors differed past the head while being the same function. Two genuinely distinct
        // functions cannot collide here, since the key carries their signatures.
        val seenHeads = mutableSetOf<Pair<Int, String>>()
        for (r in spans.ranges) {
            val closeLine = with(spans) { r.span.last }
            val cLines = renderer.decompile(r.func).lines
            val head = cLines.firstOrNull() ?: continue
            // Bodied before the duplicate check, not after: [bodied] is what tells the brace pass
            // whose delimiters a body already carries, and a copy dropped as a duplicate is covered
            // by the copy that stayed. Marking only the survivor left the dropped one's `}` to be
            // emitted on its own, which clang reports as an extraneous closing brace.
            bodied += r.func
            if (!seenHeads.add(r.start to head.text)) continue

            // The body may borrow the contiguous blank rows after its span when it outgrows it — the
            // next function or global ends the run — so a dense body breathes instead of piling on.
            val gapEnd = ((closeLine + 1)..maxLine).takeWhile { canvasFree(it) }.lastOrNull() ?: closeLine
            // AFTER, not EXACT: aliased copies (ctor C1/C2, dtor D0/D1/D2) share a start line and
            // decompile to identical heads, so under EXACT the two heads merged into one `{` while
            // their two bodies each kept a `}`. Each copy keeps its own opener and slides if it must.
            // The two declaration sets are one set seen twice. Ghidra recovers what it can from the
            // frame and names it from the applied symbols; stabs has the rest, with gcc's own types.
            // Merged by name into the head — the head already *is* the declaration block, so a stabs
            // local has somewhere to go that isn't a row the body wants. Kept out of `dedup` so a
            // later pass can still place a same-named file-scope declaration.
            val vars = varsOf(r.func).distinctBy { it.name }
            val extra = vars.filterNot { it.name in head.declares }
            // Storage goes in one trailing block comment rather than beside each declarator: the head
            // groups same-typed locals into `int a,b,c;`, so there is no per-name position to annotate
            // without breaking the grouping. Looked up by name, so it covers Ghidra's own declarations
            // too — annotating only the merged extras reached 2 of unpackfile's locals instead of all
            // of them. A `//` here would comment out the rest of the row.
            val storage = vars.filter { it.role != null }
                .sortedWith(compareBy({ it.role?.startsWith("Stack") != true }, { it.role }, { it.name }))
                .joinToString { "${it.name}=${it.role}" }
            val member = head.asMemberDefinition()
            val text = member.text + extra.joinToString("") { " ${it.text}" } +
                storage.takeIf { it.isNotEmpty() }?.let { " /* storage: $it */" }.orEmpty()

            // An anchorless region has no line of its own to render at, so as a claim it floats away
            // from the function it belongs to — and for a body that is entirely inlined it is the only
            // region there is, carrying the function's closing brace with it. `Image::size` was one
            // region reading `} /* ⇐ inlines stl_iterator.h … */`; its `}` drifted off and its head's
            // `{` swallowed every function below, so `operator[]` ran from L41 to L128 with `set`,
            // `size` and `bytesize` nested inside it. Fold those onto the last row that does have a
            // place: the last anchored region, or the head.
            val (anchored, floating) = r.func.regionsOf(cLines).dropInlined(r.func).partition { it.anchor != null }
            val tail = floating.flatMap { r -> r.lines }.filter { it.text.isNotBlank() }
            if (anchored.isNotEmpty()) anchored.last().lines.addAll(tail.map { it.copy(address = null, depth = 0) })

            // Head and body nested together, the same rule [wrapAsDefinition] applies to inlined
            // stretches. The brace pass cannot cover this, a bodied function being exactly the case
            // it steps aside for: an accessor whose body is entirely inlined — `Image::size` — keeps
            // no statement of its own after [dropInlined], so its `{` stood open and swallowed every
            // function below, `operator[]` running from image.cpp L41 to L128 with `set`, `size` and
            // `bytesize` inside it.
            val body = anchored.flatMap { r -> r.lines } + if (anchored.isEmpty()) tail else listOf()
            val (openers, closers) = braceFix(
                (member.braces.asSequence() + body.asSequence().flatMap { it.braces }).map { it.char },
            )
                .let { (o, c) -> "{".repeat(o) to "}".repeat(c) }
            this += Claim(
                Owner.FUNCTION_BODY,
                r.start,
                listOf(
                    Row(
                        if (anchored.isEmpty()) {
                            (listOf(text + openers) + tail.map { it.text }).joinToString(" ") + closers
                        } else {
                            text + openers
                        },
                        note = "L ${r.start}",
                        cuts = member.booleanCuts,
                    ),
                ),
                anchoring = Anchoring.AFTER,
                limit = gapEnd,
            )
            if (closers.isNotEmpty()) {
                anchored.lastOrNull()?.let {
                    it.lines += DecompLine.synthetic(closers)
                }
            }

            addAll(claimsFor(anchored, gapEnd, floor = r.start))
        }

        // The code this file contributed to *other* files' functions. gcc inlined it from here, so its
        // N_SLINEs name this file and its lines belong on this canvas. A header line is compiled into
        // every call site, so identical copies collapse to one tagged `×N`.
        //
        // Each function's stretches are wrapped in that function's own definition. Standing bare they
        // were statements at file scope, which no C++ construct admits — the single largest source of
        // parse errors in the render, and the reason a header view could not be compiled or even
        // reliably brace-matched. Balancing each stretch on its own (the old `balance()`) made every
        // one self-contained but left them all outside any function; the wrapper subsumes it, since a
        // definition balances the group as a whole.
        val inlined = index.functions
            .asSequence()
            .filter { f -> f !in rawFuncs && f.lineEntries.any { it.source == source } }
            .flatMap { f -> f.regionsOf(renderer.decompile(f).lines).dropInlined(f).map { f to it } }
            .filter { (_, r) -> r.anchor != null }
            .groupBy { (f, r) -> Triple(f, r.anchor, r.lines.map { it.text }) }
            .map { (_, copies) -> copies.first().also { (_, r) -> r.copies = copies.size } }
            .sortedBy { (_, r) -> r.anchor }
            // Adjacent stretches of one function share a wrapper. They cannot interleave with another
            // function's by definition, so nesting is safe, and one `vector<Exclusion,…>::operator=`
            // signature stands over its five consecutive stretches instead of being repeated above
            // each — 644 wrapper heads on unpackfile down to what the functions actually need.
            .fold(mutableListOf<Pair<Func, MutableList<Region>>>()) { acc, (f, r) ->
                acc.lastOrNull()?.takeIf { it.first == f }?.second?.add(r) ?: acc.add(f to mutableListOf(r))
                acc
            }
            .flatMap { (f, group) -> wrapAsDefinition(f, group) }
        addAll(claimsFor(inlined, maxLine, owner = Owner.INLINED_BODY))
    }

    /**
     * Enclose [group] — consecutive stretches of [func] that gcc compiled from *this* file — in a definition of
     * [func], so it reads as the body it is rather than as loose statements at file scope.
     *
     * Consecutive stretches only, never all of a function's. Two functions inlined from one header
     * interleave by line, so a wrapper spanning everything one function contributed nests as
     * `A{ B{ A} B}` — that took unpackfile from 7 rows of negative nesting to 14. Adjacent stretches
     * cannot interleave, so a wrapper over a run of them is safe and self-contained; [braceFix] gives
     * it both ends, so a group that starts mid-block (`} else {`) opens one rather than closing one
     * it never opened.
     *
     * The wrapper is a *free* function, deliberately. The class is usually not declared in this view,
     * so `Class::method` would not resolve and an implicit `this` would have nothing to bind to; the
     * explicit parameter stays, renamed along with its uses in the body because `this` is a keyword.
     *
     * It is named for the *inlined* stretch rather than for [func], so it is the definition of the
     * `__inline_…` the .cpp calls; which function did the inlining rides along as a comment, that
     * being a fact about the call site rather than about this body.
     */
    private fun wrapAsDefinition(func: Func, group: List<Region>): List<Region> =
        // One wrapper per pseudo-function, not per run: the stretches gcc bracketed together are the
        // body of one inline function, and the call site in the .cpp names it. Consecutive stretches
        // of the *same* one still share a wrapper, which is what the run-grouping was for.
        group.chunkedBy { it.pseudoName() }.flatMap { run ->
            val first = run.first()
            for (r in run) r.lines.replaceAll { it.copy(text = it.renameThis(SELF)) }
            first.lines.add(0, DecompLine.synthetic(first.definitionHead(func)))
            val (openers, closers) = braceFix(
                run.asSequence().flatMap { r ->
                    r.lines.asSequence().flatMap { it.braces }.map { it.char }
                },
            )
            if (openers > 0) first.lines.add(1, DecompLine.synthetic("{".repeat(openers)))
            if (closers > 0) run.last().lines += DecompLine.synthetic("}".repeat(closers))
            run
        }

    /**
     * [regions] as claims: none allowed to slide past [limit], none to rise above [floor] — the row
     * its function opened on — or above the region before it. See [nestingRows] for why the order has
     * to be total. The label still names the line gcc gave, so provenance survives the clamp.
     */
    private fun claimsFor(regions: List<Region>, limit: Int, floor: Int = 1, owner: Owner = Owner.FUNCTION_BODY) =
        nestingRows(regions.map { it.anchor }, floor).zip(regions) { row, r ->
            Claim(
                owner,
                row.takeIf { r.anchor != null },
                r.lines.map {
                    Row(it.text, it.depth, r.label(r.anchor ?: 0).takeIf { _ -> !r.foreign }, it.booleanCuts)
                },
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

        /**
         * The inlined function's own parameters, in the order gcc declared them.
         *
         * gcc keeps no trace of the call it inlined away *except* this: the stretch's lexical block
         * owns the callee's variables, under the callee's names, with the storage they were given in
         * the caller's frame — `stl_construct.h` comes out `__first` in dbx register 0 and `__last`
         * in 2, which is `_Construct(__first, __last)`. Every foreign block in the corpus owns
         * between one and four, so the leading ones are the parameters and any tail is the callee's
         * own locals; we cannot tell which is which, and printing all of them is the honest reading.
         *
         * Record order is declaration order — the stream position gcc emitted them at.
         *
         * Found by address, not by the block [DecompLine] carries: that one is the block covering
         * *every* address its line touches and is null wherever they disagree, which §28 measured at
         * 70% of inlined lines — the parameter lists came out empty. The stretch's first N_SLINE
         * address has exactly one innermost block, and it is the one gcc bracketed for the inlined
         * body, so its source is the file the stretch came from; anything else is the caller's own
         * block and owns the caller's own locals.
         */
        fun inlineParams(inliner: Func) = entries.minOfOrNull { it.addr }
            ?.let { inliner.blockAt(it) }
            ?.takeIf { it.source == (file ?: source) }
            ?.locals.orEmpty()
            .sortedBy { it.recordIndex }

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
         * `__inline_stl_iterator_h_633` — the header line this stretch was compiled from, as an
         * identifier.
         *
         * The same string from either side, which is what lets the call in the .cpp and the
         * definition in the header name each other: [file] identifies the stretch when we are the
         * caller and [source] when we are the header it was written in, and both label the same
         * entries, so both read the same lines off them.
         */
        fun pseudoName(): String? {
            val own = entries.filter { it.source == (file ?: source) }.ifEmpty { return null }
            val lo = own.minOf { it.line }
            val hi = own.maxOf { it.line }
            val stem = (file ?: source).substringAfterLast('/') + "_$lo" + if (hi > lo) "_$hi" else ""
            return "__inline_" + stem.replace(NON_IDENTIFIER, "_")
        }

        /**
         * The head of this stretch's definition, as the file it was written in should show it —
         * `void __inline_stl_construct_h_101(Exclusion * __first, Exclusion * __last)` — matching the
         * call the inlining .cpp renders, with which function did the inlining noted alongside.
         *
         * Falls back to [inliner]'s own signature where the stretch has no name, gcc having given its
         * addresses no N_SLINE here so there is no line to call it after. That is what every wrapper
         * used to be.
         */
        fun definitionHead(inliner: Func): String {
            val id = pseudoName()
                ?: return (
                    program.functionManager.getFunctionAt(inliner.addr)?.prototype(rename = ::asFree)
                        ?: inliner.name
                    ) +
                    " {"
            val params = inlineParams(inliner).mapNotNull { p ->
                (p.body as? SymbolDecl.Local)?.let { it.type.renderDecl(asFree(it.name), index, renderer.shortener) }
            }
            return "void $id(${params.joinToString()}) { " + "/* inlined into ${inliner.name} */"
        }

        /**
         * The inlined stretch written as the call gcc turned into it —
         * `uVar1 = __inline_stl_iterator_h_633(__first, this);` — a statement rather than the
         * `⇐ inlines …` note it replaces, because a note is not something the reader can follow. The
         * name says which header line the code came from just as the note did, and the parentheses
         * say which of the values in scope went into it.
         *
         * Arguments come from [inlineParams] where gcc bracketed the stretch: each is a register or
         * frame slot, so what the caller passed is whatever the decompiler calls that storage here
         * ([VarFlow.nameAt]). Where it calls it nothing — the local we handed Ghidra did not stick —
         * the callee's own name for it stands in, which is at least what gcc put there. Unbracketed
         * stretches have no parameter list to go on and fall back to dataflow ([VarFlow.crossing]).
         *
         * The extent is the set of N_SLINE addresses the stretch's statements were attributed to —
         * the same per-address answer that put those statements in this region, applied to p-code
         * instead of lines, so the two agree by construction.
         */
        fun pseudoCall(inliner: Func, flow: VarFlow, entryAddrOf: (Address) -> Address?): String? {
            val id = pseudoName() ?: return null
            val extent = entries.mapTo(mutableSetOf()) { it.addr }
            val (crossingIn, crossingOut) = flow.crossing { entryAddrOf(it) in extent }
            val assign = crossingOut.firstOrNull()?.let { "$it = " }.orEmpty()
            val start = entries.minOfOrNull { it.addr }
                ?: return "$assign$id(${crossingIn.joinToString()});"
            val args = inlineParams(inliner)
                .ifEmpty { return "$assign$id(${crossingIn.joinToString()});" }
                .map { p ->
                    p.storageAddress(program)?.let { flow.nameAt(it, start) }
                        ?: (p.body as? SymbolDecl.Local)?.name.orEmpty()
                }
            return "$assign$id(${args.joinToString()});"
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
    private fun Func.regionsOf(cLines: List<DecompLine>): List<Region> = buildList {
        val slines = lineEntries.sortedBy { it.addr }
        var currentKey: Any? = null
        for (dl in cLines.drop(1)) {
            val entry = dl.address?.let { a -> slines.lastOrNull { it.addr <= a } }
            val block = dl.block?.takeIf { it.source != source }
            // An addressless row (a bare brace) belongs to whatever it follows.
            val key = when {
                entry == null -> currentKey
                entry.source != source -> block ?: entry.source
                else -> entry.line
            }
            if (isEmpty() || key != currentKey) {
                add(Region((block?.source ?: entry?.source)?.takeIf { it != source }))
            }
            last().lines += dl
            entry?.let { last().entries += it }
            currentKey = key
        }
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
    private fun List<Region>.dropInlined(func: Func): List<Region> {
        val kept = mutableListOf<Region>()
        var marks = ""
        var depth = 0

        // A pseudo-call only reads as one from the calling side. In the header's own view the dropped
        // regions are the *caller's* code around the stretch this file contributed — not something
        // this file inlined — so there it stays a note.
        val calls = with(index) { func.source() } == source
        val slines = func.lineEntries.sortedBy { it.addr }
        val owner = mutableMapOf<Address, Address?>()
        fun entryAddrOf(a: Address) = owner.getOrPut(a) { slines.lastOrNull { it.addr <= a }?.addr }

        /**
         * Fold what an inlined stretch left behind onto the last row of the statement it *followed* —
         * the position it occupied in the body.
         *
         * Onto the region already kept, therefore, not the one about to be: appending to the next
         * region's last row carried the braces over that region's statements, so a `}` closing a block
         * the inlined code had opened landed after code that was still inside it. Brace counts stayed
         * balanced — the same braces, in the wrong order — while the nesting did not, which is how
         * xvimage.cpp's first constructor closed two rows early and left `(this->_base_Image).vfptr =
         * …` parsing at file scope. A leading inlined stretch has no preceding statement, so it gets
         * the same empty carrier as an all-inlined body.
         */
        fun flush() {
            if (marks.isEmpty() && depth == 0) return
            // A one-line accessor whose body is *all* inlined — Image::size — keeps nothing of its own
            // to fold onto, and its brace delta would be discarded, leaving its head's `{` hanging.
            if (kept.isEmpty()) kept += Region(null).also { it.lines += DecompLine.synthetic("") }
            val r = kept.last()
            val braces = if (depth > 0) "{".repeat(depth) else "}".repeat(-depth)
            val last = r.lines.lastOrNull() ?: return
            // Marker before the braces, not after. A block whose whole content was inlined away closes
            // immediately, and with the marker outside it read as `if (index < uVar1) { } /* ⇐ inlines
            // stl_iterator.h L 584 */` — an empty block with a footnote. Inside, the same tokens say
            // what is actually true: `if (index < uVar1) { /* ⇐ inlines stl_iterator.h L 584 */ }`,
            // the body is over there. 80 rows on unpackfile read as empty blocks.
            // Ghidra emits an already-closed block as `{}`; the marker goes between its braces for the
            // same reason, so an inlined-away loop body reads `for (…) { /* ⇐ inlines … */ }`. A `{}`
            // with no marker is Ghidra's own empty loop and stays as it is.
            val opener = last.braces.takeLast(2)
                .takeIf {
                    marks.isNotEmpty() &&
                        it.map(Brace::char) == EMPTY_BLOCK &&
                        it.last().at == last.text.lastIndex
                }
                ?.first()
            val marked = opener?.let { last.text.substring(0, it.at + 1) + marks + " }" } ?: (last.text + marks)
            // The splice moved the closer the marks went inside; everything else kept its place.
            val moved = if (opener == null) last.braces else last.braces.dropLast(1) + Brace('}', marked.lastIndex)
            val text = listOf(marked, braces).filter(String::isNotEmpty).joinToString(" ")
            r.lines[r.lines.lastIndex] = last.copy(
                text = text,
                braces = moved + braces.mapIndexed { i, c -> Brace(c, text.length - braces.length + i) },
            )
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
                depth += r.lines.sumOf { l -> l.braces.sumOf { if (it.char == '{') 1 else -1 } }
                val call = if (calls) r.pseudoCall(func, renderer.decompile(func).flow, ::entryAddrOf) else null
                (call ?: r.labelOrNull()?.let { "/* ⇐ inlines $it */" })?.let { marks += " $it" }
                continue
            }
            flush()
            kept += r
        }
        flush()
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
        for (r1 in spans.ranges) {
            val interior = with(spans) { r1.interior } ?: continue
            val name1 = r1.func.demangledName
            val where = "inside $name1 [L$interior]"
            for (r2 in spans.ranges) {
                if (r2.func === r1.func) continue
                val name2 = r2.func.demangledName
                if (name2 == name1) continue
                if (r2.start in interior) {
                    anomalies += "skeleton[$source]: function $name2 opens at L${r2.start} $where"
                }
                if (r2.endInclusive in interior && r2.start !in interior) {
                    anomalies += "skeleton[$source]: function $name2 closes at L${r2.endInclusive} $where"
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
