package ghistabs.render

import ghidra.program.model.address.Address
import ghistabs.chunkedBy
import ghistabs.harvest.Func
import ghistabs.harvest.GhidraSourceFile
import ghistabs.harvest.LineEntry
import ghistabs.harvest.blockAt
import ghistabs.parse.SymbolDecl

/**
 * One inlined region, or the statements of one this-file source line. [file] is the file an inlined
 * region was compiled from, null for code belonging to *this* render's source — which is what makes
 * the split symmetric: the same call answers "what of this function is mine" whether the function is
 * defined here or merely inlines code from here.
 */
class Region(private val ctx: RenderContext, val file: GhidraSourceFile?) {
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
        ?.takeIf { it.source == (file ?: ctx.source) }
        ?.locals.orEmpty()
        .sortedBy { it.recordIndex }

    /** How many identical copies of this region the binary holds — one per site it was inlined at. */
    var copies = 1
    val foreign get() = file != null

    /** The this-file line the region belongs on. Inlined code has none; it rides its call site. */
    val anchor get() = if (foreign) null else entries.filter { it.source == ctx.source }.minOfOrNull { it.line }

    // `header.h L a-b` for an inlined region, `L n` for a this-file line — null when gcc gave the
    // region's addresses no N_SLINE in the file it belongs to, so there is no line to name. A
    // block-bounded region may cover entries from several files; only those from the file it is
    // labelled with bound the range.
    fun labelOrNull(): String? {
        val own = entries.filter { it.source == (file ?: ctx.source) }.ifEmpty { return null }
        val lo = own.minOf { it.line }
        val hi = own.maxOf { it.line }
        return file?.filename?.plus(" ").orEmpty() + "L $lo" + if (hi > lo) "-$hi" else ""
    }

    fun label(fallback: Int) = (labelOrNull() ?: "L $fallback") + if (copies > 1) " ×$copies" else ""

    /**
     * `_M_deallocate__stl_vector_h_123`, or `__inline_stl_iterator_h_633` where the function that
     * was inlined has no name to give — the header line this stretch was compiled from, as an
     * identifier.
     *
     * The same string from either side, which is what lets the call in the .cpp and the
     * definition in the header name each other: [file] identifies the stretch when we are the
     * caller and [ctx.source] when we are the header it was written in, and both label the same
     * entries, so both read the same lines off them — and both ask the same file's real source for
     * the name, so the source root cannot make the two disagree either.
     *
     * The line stays in the identifier even when the name is known. Two stretches of one function
     * inlined from different lines are different code, and `_M_deallocate` alone would name both.
     */
    fun pseudoName(): String? {
        val own = entries.filter { it.source == origin }.ifEmpty { return null }
        val lo = own.minOf { it.line }
        val hi = own.maxOf { it.line }
        val stem = (origin.filename + "_$lo" + if (hi > lo) "_$hi" else "").sanitizeIdentifier()
        return definition()?.name?.asIdentifier()?.plus("__$stem") ?: "__inline_$stem"
    }

    /** The file this stretch was compiled from — [file] when we are the caller, ours when we wrote it. */
    private val origin get() = file ?: ctx.source

    /** What the real source says this stretch is part of, where `--source-root` resolved the file. */
    private fun definition() = entries.filter { it.source == origin }.minOfOrNull { it.line }
        ?.let { ctx.enclosing(origin, it) }

    /**
     * The head of this stretch's definition, as the file it was written in should show it —
     * `void __inline_stl_construct_h_101(Exclusion * __first, Exclusion * __last)` — matching the
     * call the inlining .cpp renders, with which function did the inlining noted alongside.
     *
     * Falls back to [inliner]'s own signature where the stretch has no name, gcc having given its
     * addresses no N_SLINE here so there is no line to call it after. That is what every wrapper
     * used to be.
     *
     * The real source's parameter list stands in only where gcc's block scope gave none — where it
     * gave one it is the better of the two, being the *instantiated* types (`Exclusion *`, not
     * `_ForwardIterator`) under the same names gcc took from the source anyway, and it is what
     * [pseudoCall] passes arguments for. Substituting it wholesale would let head and call disagree
     * on their arity, which is the one property that makes the two views read as one function.
     */
    fun definitionHead(inliner: Func): String {
        val id = pseudoName() ?: return (
            ctx.program.functionManager.getFunctionAt(inliner.addr)
                ?.prototype(rename = ::asFree) ?: inliner.name
            ) + " {"
        val params = inlineParams(inliner).mapNotNull { p ->
            (p.body as? SymbolDecl.Local)?.let { with(ctx) { it.type.renderDecl(asFree(it.name)) } }
        }
        val list = params.joinToString().ifEmpty { definition()?.params.orEmpty() }
        return "void $id($list) { " + "/* inlined into ${inliner.name} */"
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
                p.storageAddress(ctx.program)?.let { flow.nameAt(it, start) }
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
fun FileRenderer.regionsOf(func: Func, cLines: List<DecompLine>): List<Region> = buildList {
    val slines = func.lineEntries.sortedBy { it.addr }
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
            add(Region(this@regionsOf, (block?.source ?: entry?.source).takeIf { it != source }))
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
 * file's code opened: unfile.cpp went from 61/61 braces to 15/13 and stopped parsing. Keeping
 * the region's brace-*only* rows doesn't fix it either — those are all closers, an opener riding
 * its statement (`if (x) {`) — which swung it the other way, to 15/59.
 *
 * So each dropped region leaves behind its net brace delta. Nesting depth is a property of the
 * body, not of any one file — gcc gives a brace row no N_SLINE, and the block it closes may have
 * been opened by code from any file the function inlined — so every view can carry it, and every
 * view balances, because the body they were split out of did.
 */
fun FileRenderer.dropInlined(regions: List<Region>, func: Func): List<Region> = buildList {
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
     * file.cpp's first constructor closed two rows early and left `(this->_base_Image).vfptr =
     * …` parsing at file scope. A leading inlined stretch has no preceding statement, so it gets
     * the same empty carrier as an all-inlined body.
     */
    fun flush() {
        if (marks.isEmpty() && depth == 0) return
        // A one-line accessor whose body is *all* inlined — Image::size — keeps nothing of its own
        // to fold onto, and its brace delta would be discarded, leaving its head's `{` hanging.
        if (isEmpty()) this += Region(this@dropInlined, null).also { it.lines += DecompLine.synthetic("") }
        val r = last()
        val braces = if (depth > 0) "{".repeat(depth) else "}".repeat(-depth)
        val last = r.lines.lastOrNull() ?: return
        // Marker before the braces, not after. A block whose whole content was inlined away closes
        // immediately, and with the marker outside it read as `if (index < uVar1) { } /* ⇐ inlines
        // stl_iterator.h L 584 */` — an empty block with a footnote. Inside, the same tokens say
        // what is actually true: `if (index < uVar1) { /* ⇐ inlines stl_iterator.h L 584 */ }`,
        // the body is over there. 80 rows on unbouniaf read as empty blocks.
        // Ghidra emits an already-closed block as `{}`; the marker goes between its braces for the
        // same reason, so an inlined-away loop body reads `for (…) { /* ⇐ inlines … */ }`. A `{}`
        // with no marker is Ghidra's own empty loop and stays as it is.
        val opener = last.braces.takeLast(2)
            .takeIf { marks.isNotEmpty() && it.isEmptyBlock() && it.last().at == last.text.lastIndex }
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

    for (r in regions) {
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
        this += r
    }
    flush()
}

/**
 * Enclose [group] — consecutive stretches of [func] that gcc compiled from *this* file — in a definition of
 * [func], so it reads as the body it is rather than as loose statements at file scope.
 *
 * Consecutive stretches only, never all of a function's. Two functions inlined from one header
 * interleave by line, so a wrapper spanning everything one function contributed nests as
 * `A{ B{ A} B}` — that took unbouniaf from 7 rows of negative nesting to 14. Adjacent stretches
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
fun List<Region>.wrapAsDefinition(func: Func): List<Region> =
    // One wrapper per pseudo-function, not per run: the stretches gcc bracketed together are the
    // body of one inline function, and the call site in the .cpp names it. Consecutive stretches
    // of the *same* one still share a wrapper, which is what the run-grouping was for.
    chunkedBy { it.pseudoName() }.flatMap { run ->
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
 * [regions] as claims: none allowed to slide past the [limit] its own row admits — the next
 * function's opener, so a stretch cannot come to rest inside a function it is no part of — none to
 * rise above [floor] — the row its function opened on — or above the region before it. See
 * [nestingRows] for why the order has to be total. The label still names the line gcc gave, so
 * provenance survives the clamp.
 */
fun List<Region>.claimsFor(limit: (row: Int) -> Int?, floor: Int = 1, owner: Owner = Owner.FUNCTION_BODY) =
    nestingRows(map { it.anchor }, floor).zip(this) { row, r ->
        Claim(
            owner,
            row.takeIf { r.anchor != null },
            r.lines.map {
                Row(it.text, it.depth, r.label(r.anchor ?: 0).takeIf { _ -> !r.foreign }, it.booleanCuts)
            },
            Fit.ELASTIC,
            anchoring = Anchoring.AFTER,
            limit = limit(row),
        )
    }
