package ghistabs.render

import ghidra.program.model.address.Address
import ghistabs.chunkOf
import ghistabs.harvest.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

class FileRenderer(override val renderer: Renderer, override val source: GhidraSourceFile) : RenderContext {
    private val rawFuncs = index.functionsBySource[source].orEmpty()
    private val lines = renderer.linesBySource[source].orEmpty()
    private val typeDecls = index.typesBySource[source].orEmpty().filter { it.name != null && it.line != null }
    private val statics = index.staticsBySource[source].orEmpty()

    private val spans = FunctionSpans.of(rawFuncs, source)
    override fun Int?.indentAt() = if (this != null && spans.inFunction(this)) 4 else 0

    private val lineExtent = lines.maxOfOrNull { it.lineNumber }
    private val codeExtent = extentOf(lineExtent, spans.maxStabLine)
    private val staticsExtent = statics.mapNotNull { it.line }.maxOrNull()
    private val typesExtent = typeDecls.mapNotNull { it.line }.maxOrNull()

    /**
     * The file's real length, where `--source-root` resolved it and phase 2's agreement guard kept
     * it. This is the one input to the extents below that is not derived from the declarations they
     * judge, so where it exists §43's circularity is simply gone.
     */
    private val sourceLength = believedLength(renderer.lengthOf(source), codeExtent) { length ->
        index.warn("source-length-conflict", "$source: code reaches L$codeExtent of $length lines")
    }

    /**
     * How far gcc showed evidence of activity. Past it, a declaration's line is not to be trusted.
     *
     * A CU is measured by its code and by nothing a declaration says — the misattributed declarations
     * this exists to catch would otherwise define the extent by the very thing it judges (§38). An
     * included file contributes N_SLINEs only where its code was inlined elsewhere, so there
     * declarations are the only evidence there is. Which regime applies is what gcc's `N_SO` says,
     * not whether the file has spans: that leaks both ways.
     *
     * A header the source root resolved is not estimated at all — [sourceLength] is what it reaches.
     * A CU keeps the code-derived extent even then, its real length being no evidence about which of
     * its *own* declarations gcc misfiled.
     */
    private val staleAfter = when {
        source in index.compilationUnits -> codeExtent
        else -> sourceLength ?: extentOf(codeExtent, staticsExtent, typesExtent)
    }

    // A decl at this line is misattributed (stale N_SOL) if it sits past the file's activity.
    override fun Int?.isStale() = beyond(staleAfter)

    /** A declaration several files claim at one line — at most one of them rightly. */
    private fun Type.disputed() = when (body) {
        is TypeDecl.Struct, is TypeDecl.Enum -> index.conflictedTemplateDecls
        else -> index.conflictedTypedefDecls
    }.let { declKey() in it }

    /**
     * How far this file's *own* content reaches — code, globals, and the type declarations not
     * themselves in dispute. Not a judgement about staleness like [staleAfter]: the yardstick for
     * whether a line several files claim could be this one's. [sourceLength] answers it outright,
     * for a CU as much as a header — how long the file is *is* how far its content can reach.
     */
    private val reachesTo = sourceLength ?: extentOf(
        codeExtent,
        staticsExtent,
        typeDecls.filterNot { it.disputed() }.mapNotNull { it.line }.maxOrNull(),
    )

    /**
     * [disputed], on a line this file cannot reach.
     *
     * An uncontested declaration past the reach stays: that is `class XVImage` at xvimage.h L36, four
     * lines past the last of the header that happened to be inlined, and it is the file's own content.
     */
    private fun Type.misfiled() = disputed() && line.beyond(reachesTo)

    /**
     * How tall the canvas is: attested activity plus every declaration that is not [isStale]. A
     * misattributed one is never laid out, so letting it set the height rendered `main.cpp` as 1456
     * rows for 166 lines of code (§38). The claim passes must therefore *not* gate on this — they
     * build everything and let the allocator turn a claim past the end away as [OFF_CANVAS], which
     * [write] carries to the displaced appendix. Filtering at the source loses it silently.
     */
    private val canvas = Canvas(
        extentOf(
            spans.maxLine, // includes possible closing brace
            lineExtent,
            typeDecls.filterNot { it.line.isStale() }.mapNotNull { it.line }.maxOrNull(),
            statics.filterNot { it.line.isStale() }.mapNotNull { it.line }.maxOrNull(),
        ),
    )

    fun render(): String {
        // Nothing sits on a usable line, but the file can still hold anonymous aggregates and
        // declarations whose line is unusable — which is what the appendix is for. libstdc++'s
        // `*-inst.cc` are whole CUs of them, and returning before the claim passes dropped 71 types
        // and 80 typedefs from the xmltest render without a word.
        if (canvas.isEmpty()) {
            displaced += (typedefClaims() + globalClaims() + typeBodyClaims()).map { Dropped(it, MISATTRIBUTED) }
            return anonAggregateAppendix() + instantiationAppendix() + displacedAppendix()
        }

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
        write(allocate(placeable, canvas))
        // Annotations, not content: they carry no code and share a row with whatever holds it, so
        // they are never claims. In decomp mode the body restates them, so they go where it landed.
        emitSlineAnnotations()
        reportAnomalies()
        // Trailing blank/stale lines are trimmed only in decomp mode; skeleton output
        // stays fully source-aligned.
        val rendered = canvas.render(trim = renderer.decomp != null, compact = !renderer.lineAligned)
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

    // Anonymous aggregates carry no source line (line == null), so they can't be placed inline
    // on the line-based canvas. Append them as a skeleton-only diagnostic block under their synthetic
    // Anon_ id; decomp omits them entirely. Deduped by ghidraName (content-hashed, §20).
    private fun anonAggregateAppendix(): String {
        if (renderer.mode != Mode.SKELETON) return ""
        val anon = renderer.index.anonAggregates[source]

        if (anon.isNullOrEmpty()) return ""
        val blocks = anon.joinToString("\n\n") { ast ->
            when (val body = ast.body) {
                is TypeDecl.Struct -> {
                    val members = body.renderFull(ast.ghidraName.simpleTypeName())
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
     * Instantiations that shared a line with the one rendered inline. Every instantiation of a
     * template carries the *template's* line, so only one can hold that row; the rest would otherwise
     * vanish behind the `N instantiations` count. They differ in exactly the way that matters — the
     * substituted types — so they go here in full rather than being summarised away.
     */
    private val mergedInstantiations = mutableListOf<Type>()

    private fun instantiationAppendix(): String {
        val (bodied, opaque) = mergedInstantiations
            .sortedWith(compareBy({ it.line }, { it.name }))
            .partition { it.body.memberCount() > 0 }
        // An instantiation with no members says nothing as `class X<…> {  }; /* 1 bytes */`, and 55 of
        // 68 appendix rows were exactly that. Its *name* is still the point — which specialisations
        // exist, which the `×N` count on the declaring line cannot say — so they list one line per
        // source line instead of one block each.
        val blocks = (
            bodied.map { "/* L${it.line} */ ${it.oneLineBody()}" } +
                opaque.groupBy { it.line }.map { (line, group) ->
                    "/* L$line */ " + group.mapNotNull { it.name }
                        .joinToString(", ") { shortener?.shortenedOrNull(it) ?: it } + ";"
                }
            ).sorted().joinToString("\n").ifEmpty { return "" }
        return "\n\n/* ── further template instantiations (sharing a declared line above) ── */\n\n$blocks\n"
    }

    /**
     * Skeleton: one `// L n @ 0xADDR[: code-unit]` per (line, code-unit) group — an address map,
     * which is what that mode is for.
     *
     * Decomp: the same fact as provenance instead. A header line whose code we did not render here
     * was compiled into somebody else's function, and naming that function is the useful half.
     */
    private fun emitSlineAnnotations() {
        // Aggregates the addresses of N_SLINEs sharing a (line, codeUnit) into one annotation.
        data class SliceKey(val line: Int, val codeUnit: String)

        val byKey = mutableMapOf<SliceKey, MutableSet<Address>>()
        for (entry in lines) {
            if (entry.lineNumber !in canvas) continue
            val addr = entry.baseAddress
            byKey.getOrPut(SliceKey(entry.lineNumber, addr.render(program) ?: "")) { sortedSetOf() } += addr
        }
        if (renderer.decomp == null) {
            for ((key, addrs) in byKey) {
                val runs = formatAddrRuns(addrs.toList(), program)
                val note = if (key.codeUnit.isEmpty()) runs else "$runs: ${key.codeUnit}"
                canvas[key.line] += Fragment(key.line.indentAt(), note = note, shape = NoteShape.SLINE)
            }
            return
        }
        // One marker per line naming every function this line's code ended up inside — but only where
        // that function belongs to *another* file. A line of main.cpp compiled into main was not
        // inlined anywhere; Ghidra simply folded it into a neighbouring statement, and saying
        // "inlined into main" inside main is nonsense. Rows the decompilation already occupies say it
        // better than any annotation could.
        val own = rawFuncs.mapTo(mutableSetOf()) { it.addr }
        for ((line, addrs) in lines.filter {
            it.lineNumber in canvas
        }.groupBy({ it.lineNumber }, { it.baseAddress })) {
            if (canvas[line].fragments.any { it.shape == NoteShape.PROVENANCE }) continue
            val fns = addrs
                .mapNotNull { program.functionManager.getFunctionContaining(it) }
                .filterNot { it.entryPoint in own }
                .map { it.getName(true) }
                .distinct()
                .ifEmpty { continue }
            canvas[line] += Fragment(line.indentAt(), "/* inlined into ${fns.joinToString(", ")} */")
        }
    }

    private fun typedefClaims(): List<Claim> {
        data class Td(val ast: Type, val name: String, val rendered: String) {
            val line get() = ast.line
        }

        val typedefs = typeDecls
            .filter { it.body !is TypeDecl.Struct && it.body !is TypeDecl.Enum }
            .mapNotNull { ast ->
                ast.name?.let { Td(ast, it, ast.body.render()) }
            }

        // A genuine typedef has one definition site. The same alias+target recurring across a .cpp
        // is stab N_SOL splaying one libstdc++ instantiation typedef (`iterator_traits<X>::_ValueType`,
        // emitted per instantiation) whose N_SOL named the CU — flag every copy misattributed.
        // Headers are the canonical home and keep theirs; where two of them claim one typedef at one
        // line, [misfiled] settles it by reach instead.
        val splayed = if (source.filename.hasHeaderExtension()) {
            emptySet()
        } else {
            typedefs.groupBy { it.name to it.rendered }.filterValues { it.size > 1 }.keys
        }

        // Collapse duplicate (name, target) copies to one line. Keying on the pair — not the
        // line the old dedup used — is what makes this fire when misattribution splays a
        // typedef across several bogus lines.
        val seen = mutableSetOf<Pair<String, String>>()
        val claims = typedefs.sortedBy { it.line }.mapNotNull { (ast, name, rendered) ->
            val line = ast.line
            val key = name to rendered
            if (!seen.add(key)) {
                null
            } else {
                Claim(
                    Owner.TYPEDEF,
                    line,
                    listOf(Row("typedef $rendered $name;", line.indentAt(), note = "")),
                    stale = line.isStale() || key in splayed || ast.misfiled(),
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
                // Everything crammed onto one row keeps the indent of the statement that opens it —
                // TargetLine takes the shallowest, which let a trailing `}` drag the row to column 0.
                val indent = if (row == prev) prevIndent else content.indent
                // Identical claims merged; say how many there were rather than silently showing one.
                // Aliased copies (ctor C1/C2, dtor D0/D1/D2) are one declaration emitted N times.
                val note = content.note?.let { if (copies > 1) "$it ×$copies" else it }
                canvas[row] += Fragment(indent, content.text, note, claim.owner.noteShape)
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

    private val seenDecls = mutableSetOf<Type.Decl>()

    // One declaration per (line, name); `this` never renders. Guards every decl pass. Not bounded by
    // the canvas — a declaration past it is the allocator's to turn away, and the appendix's to show.
    private fun dedup(line: Int?, name: String) = line != null && name != "this" && seenDecls.add(Type.Decl(line, name))

    private fun varsOf(f: Func): List<Var> = (f.params + f.locals).filter { it.sourceFile == source }.mapNotNull {
        it.renderVar(renderer.showStorage)
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
                    listOf(Row(it.text, it.line.indentAt(), it.role)),
                    stale = span == null || it.line == null || it.line !in span,
                )
            }
        }
    }

    // Attributed by CU (`staticsByCu`), not `s.sourceFile`: gcc emits no `N_SOL(cu)` before N_GSYM,
    // so `sourceFile` points at the last header visited.
    //
    // gcc dates generated data (RTTI, string tables) by whatever it was emitting at the time, so a
    // global landing inside a function's braces has a wrong line, not a wrong home — it goes to the
    // appendix like any claim that lost its row. A real one carries `enclosingFunction` and stays.
    private fun globalClaims(): List<Claim> {
        val claims = statics.mapNotNull { s ->
            s.takeIf { dedup(s.line, s.body.name) }?.let { emitGlobal(s) to s }
        }
        val reasons = claims.mapNotNull { (claim, s) ->
            when {
                s.enclosingFunction != null -> null
                spans.insideBody(s.line) -> Dropped(claim, INSIDE_BODY)
                s in foreignRun -> Dropped(claim, FOREIGN_RUN)
                else -> null
            }
        }
        displaced += reasons
        val lost = reasons.mapTo(mutableSetOf()) { it.claim }
        return claims.map { it.first }.filterNot { it in lost }
    }

    /**
     * Statics this file did not declare, caught as a group rather than one at a time.
     *
     * Alone, the only proof is a collision: a file-scope definition cannot sit between a function's
     * braces, so a line inside an attested span is foreign and everything else merely suspicious —
     * 2 of main.cpp's twenty `vmN_trapset_names` tables. The rest are carried by *uniformity*: an
     * arithmetic progression ascending with its addresses is one generated block, which cannot span
     * two files unbroken, so one collision condemns the run. Narrow deliberately — globals are
     * emitted in declaration order, so plain "ascending" would describe every file's global list;
     * the constant stride over three or more is the generated-table signature. See §38.
     */
    private val foreignRun: Set<StaticSymbol> by lazy {
        statics
            .filter { it.enclosingFunction == null && it.rawValue != 0L }
            .mapNotNull { s -> s.line?.to(s) }
            .sortedBy { it.second.rawValue }
            .chunkOf { run, (declLine, sym) ->
                val lastLine = run.last().first
                val step = declLine - lastLine
                val stride = run.getOrNull(run.size - 2)?.let { lastLine - it.first }
                step > 0 && (stride == null || stride == step)
            }
            .filter { run -> run.size >= 3 && run.any { spans.insideBody(it.first) } }
            .flatMap { g -> g.map { it.second } }
            .toSet()
    }

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
            // Say when the body is missing because Ghidra ran out of time, rather than leaving a
            // bodiless `sig {` that reads like a function with nothing in it (§40).
            val timedOut = if (r.func.addr in renderer.undecompiled) ", decompilation did not finish" else ""
            val openNote = if (r.isSingleLine) name else "opens $name$timedOut"
            this += Claim(Owner.FUNC_DELIM, r.start, listOf(Row(openText, note = openNote)))
            val closeLine = with(spans) { r.closeLine } ?: continue
            if (closeLine !in canvas) continue
            this += Claim(Owner.FUNC_DELIM, closeLine, listOf(Row("}", note = "closes $name")))
        }
    }

    // Struct/enum bodies spread over the blank lines below the decl; opaque types fall
    // back to a one-line forward decl.
    private fun typeBodyClaims(): List<Claim> {
        val claims = mutableListOf<Claim>()
        // Every instantiation of one template carries the *template's* line, so N of them arrive
        // for a line the source declares once. They are not peers competing for space; they are one
        // declaration seen N times. Render the fullest body and say how many there were — the same
        // answer the allocator already gives inlined copies — rather than letting one instantiation's
        // members render under another's opener, which is a class that does not exist.
        val byDecl = typeDecls
            .filter { it.body is TypeDecl.Struct || it.body is TypeDecl.Enum }
            .groupBy { it.declKey() }
            .filterKeys { it != null }
            .entries

        for ((_, group) in byDecl.sortedBy { it.key?.line }) {
            // Renders only where the line is one this file plausibly reaches: stl_vector.h's own
            // content runs past L900 and keeps its copy, image.h's stops at L53 and cannot be
            // declaring anything at L898. See [misfiled].
            if (group.first().misfiled()) {
                group.first().emitTypeBody(group.size)?.let { displaced += Dropped(it, CONFLICTED_DECL) }
                mergedInstantiations += group.drop(1)
            } else {
                // Deterministic pick: the most members, then by name, so the choice can't drift with
                // unrelated type-resolution changes.
                val ast = group.maxWith(compareBy({ it.body.memberCount() }, { it.name }))
                mergedInstantiations += group.filterNot { it === ast }
                ast.emitTypeBody(group.size)?.also { claims += it }
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

    fun Func.ownRegions() = dropInlined(regionsOf(this, renderer.decompile(this).lines), this)

    /**
     * Every decompiled statement this file should show — its own function bodies, and the code it
     * contributed to other files by being inlined. Rows claim their own source lines and win or lose
     * contested ones on [Owner] priority, replacing the retroactive `// stray:` demotion pass.
     */
    private fun decompClaims(): List<Claim> = buildList {
        // Aliased out-of-line copies — ctor C1/C2, dtor D0/D1/D2 — are one function gcc emitted at
        // several addresses, all mapped to one source line; decompiling each stacked the duplicates.
        // Keyed on (start line, signature): two distinct functions cannot collide because the key
        // carries their signatures, and nothing past the signature can be in it because Ghidra names
        // the locals per copy.
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
            if (!seenHeads.add(r.start to (head.prototype ?: head.text))) continue

            // The body may borrow the blank rows after its span when it outgrows it — up to the next
            // function's opener, past which the rows are that function's — so a dense body breathes
            // instead of piling on.
            val gapEnd = spans.barrier(r.start)
            // AFTER, not EXACT: several functions can share a start line, and under EXACT their heads
            // merged into one `{` while each body kept its `}`. Each keeps its own opener and slides
            // if it must.
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
            val (anchored, floating) = r.func.ownRegions().partition { it.anchor != null }
            // Inside the member it belongs to, a call writes `find_slt(a)`, not `find_slt(this,a)` —
            // the definition it calls has had the parameter cut, so the two halves must agree. Only
            // here: an inlined stretch is wrapped as a free function and keeps `this` as an argument.
            if (program.functionManager.getFunctionAt(r.func.addr)?.parentNamespace?.isGlobal == false) {
                anchored.forEach { region -> region.lines.replaceAll { it.withoutThisArguments() } }
            }
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

            addAll(anchored.claimsFor(spans::barrier, floor = r.start))
        }

        // The code this file contributed to *other* files' functions. gcc inlined it from here, so
        // its N_SLINEs name this file and its lines belong on this canvas; a header line compiled
        // into every call site collapses to one copy tagged `×N`. Each function's stretches are
        // wrapped in that function's own definition — bare, they are statements at file scope, which
        // no C++ construct admits and nothing can brace-match.
        val inlined = index.functions
            .asSequence()
            .filter { f -> f !in rawFuncs && f.lineEntries.any { it.source == source } }
            .flatMap { f -> f.ownRegions().map { f to it } }
            .filter { (_, r) -> r.anchor != null }
            // Not by the inliner at all: a header line compiled into every call site is what the `×N`
            // exists for, and keying on who inlined it defeated that — gcc's dtor aliases D0/D1/D2
            // showed `__inline_xdvimage_cpp_30` twice, and two unrelated functions inlining one line
            // of stl_alloc.h defined `__inline_stl_alloc_h_236` twice in the same file, which is a
            // C++ redefinition. Identical text at one anchor is one stretch however many callers
            // share it; where the text differs — a template instantiated per element type — the
            // definitions differ in their parameters too and stand as legal overloads.
            .groupBy { (_, r) -> r.anchor to r.lines.map { it.text } }
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
            .flatMap { (f, group) -> group.wrapAsDefinition(f) }
        addAll(inlined.claimsFor(spans::barrier, owner = Owner.INLINED_BODY))
    }

    /** A row nothing has claimed yet — only meaningful before allocation writes anything. */
    // The headers this file pulls in, as #include lines above the first line of content: those whose
    // code was inlined here (non-.cpp N_SLINE sources), plus those defining the types its functions
    // name — resolved through `XRef`/`Ref`/`InlineDef` to the definition and its bases — so a .cpp
    // with nothing inlined still declares its dependencies. Placed within the available top room;
    // overflow stacks on the last free line rather than pushing content down.
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
            .filter { it != source && it.filename.hasHeaderExtension() }
            .map(::includeSpelling)
            .distinct()
            // System headers first, each group alphabetical — the order a source file writes them in.
            .sortedWith(compareBy({ it.startsWith("\"") }, { it }))
            .map { "#include $it" }
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
            // A decl with no line is nowhere, so it is not inside anything
            for (ast in typeDecls) {
                val line = ast.line ?: continue
                if (line !in interior) continue
                anomalies += "skeleton[$source]: type ${ast.name} declared at L$line $where"
            }
            for (s in statics) {
                val line = s.line ?: continue
                if (line !in interior) continue
                anomalies += "skeleton[$source]: global/static ${s.body.name} at L$line $where"
            }
        }
        anomalies.forEach(::println)
    }

    companion object {
        /** `open` / one indented row per item / `close`, the shape both aggregate initializers and type bodies take. */
        fun braceRows(open: String, items: List<String>, close: String, indent: Int, role: String? = null) =
            listOf(Row(open, indent, role)) + items.map { Row(it, indent + 4) } + Row(close, indent)

        /**
         * A file's length as an extent, or null where it must not be trusted — [onConflict] is told which.
         *
         * A root for the wrong version resolves happily and gives a wrong length. Only [code] may refute it,
         * being address-backed; a *declaration* past the end counts for nothing here, since that is the very
         * thing the length is here to catch. No [code] is therefore not doubt but the absence of anything
         * that could refute — a header nothing was inlined out of still knows how long it is.
         */
        internal fun believedLength(length: Int?, code: Int?, onConflict: (Int) -> Unit): Int? = when {
            length == null -> null
            code.beyond(length) -> null.also { onConflict(length) }
            else -> length
        }
    }
}

/** The furthest line anything attests to, or null where nothing does — never a zero standing in. */
internal fun extentOf(vararg lines: Int?) = lines.filterNotNull().maxOrNull()

/**
 * Past an extent, where a file that reaches nothing is reached past by everything: the extents are
 * what a line is judged against, and "no evidence" was the case that judged every line stale before
 * they could be null. A null [this] is no line at all, so it is past nothing.
 */
internal fun Int?.beyond(extent: Int?) = this != null && (extent == null || this > extent)
