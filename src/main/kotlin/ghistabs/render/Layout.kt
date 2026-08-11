package ghistabs.render

/**
 * Break a long decompiler statement across rows at its shallowest `&&`/`||` boundaries, so a crammed
 * `if` condition (Ghidra wraps then §9 rejoins onto one 300-char row) spreads into blank rows instead.
 * The operator stays at the end of its row (K&R), continuations sit one step past [depth]. Recurses
 * so each piece falls under [minLen] where its own shallower boundaries allow; a short line, or one
 * with no boundary at all, stays a single row.
 *
 * [cuts] are read off the row's tokens, not scanned back out of its characters: a `&&` is an operator
 * token and the depth comes from the paren and bracket tokens, so one inside a string literal is not
 * a boundary and one inside a call's arguments is not a shallow one.
 */
fun wrapDecompLine(text: String, depth: Int, cuts: List<Cut>, minLen: Int = 120): List<Pair<Int, String>> =
    splitCondition(text, text.indices, cuts, minLen).mapIndexed { i, s -> (if (i == 0) depth else depth + 2) to s }

private fun splitCondition(text: String, span: IntRange, cuts: List<Cut>, minLen: Int): List<String> {
    val piece = { it: IntRange -> text.substring(it.first, it.last + 1).trim() }
    if (span.last - span.first + 1 <= minLen) return listOf(piece(span))
    // Shallowest first, and only within this piece: a nested boundary is a split point for the piece
    // it ends up in, not for this one.
    val inside = cuts.filter { it.at > span.first && it.at <= span.last }
    val top = inside.minOfOrNull { it.depth } ?: return listOf(piece(span))
    val at = inside.filter { it.depth == top }.map { it.at }
    val spans = (listOf(span.first) + at).zipWithNext { a, b -> a..<b } + listOf(at.last()..span.last)
    return spans.flatMap { splitCondition(text, it, cuts, minLen) }
}

// Pure layout model: Canvas ⊃ TargetLine ⊃ Fragment.

// One piece of a line, fully semantic: [code] is the C text (null for a bare comment), [note] the
// comment payload (a role, an address run, a delimiter phrase — null for a pure-code line) and
// [shape] how that payload is spelled. The line number the tag restates is the fragment's grid
// position, so the comment is derived at render time via [commentAt], not stored.
//
// Carries no `stale` flag: a misattributed claim is partitioned into `displaced` before anything is
// written, so no fragment on the canvas was ever stale and both tests that read it were dead.
data class Fragment(
    val indent: Int = 0,
    val code: String? = null,
    val note: String? = null,
    val shape: NoteShape = NoteShape.DECLARATION,
) {
    fun commentAt(line: Int) = note?.let { commentFor(line, shape, it) }
}

// An empty block and the markers naming what was inlined out of it: `for (…) { }` followed by
// `/* ⇐ inlines stl_vector.h L 123 */`, or by the `__inline_…()` call that stands in for it.
private val EMPTY_BLOCK_MARKERS =
    Regex("""\{ *\}((?: *(?:/\* ⇐ inlines[^*]*\*/|(?:\w+ = )?__inline_\w+\([^()]*\);))+)""")

/**
 * Markers moved inside the block whose content they replace.
 *
 * [dropInlined] already does this where it can see both braces on one of its rows; what it cannot see
 * is a `{` and its `}` arriving at the row from different fragments — separate claims, or separate
 * rows crammed together by [fitRows] — and only here is the row whole. Outside, the pair reads as an
 * empty block with a footnote; inside, the same tokens say what is true: the body is over there.
 */
private fun spliceInlineMarkers(code: String) = EMPTY_BLOCK_MARKERS.replace(code) { "{ ${it.groupValues[1].trim()} }" }

// The fragments sharing source [line]. Renders all code first, all comments last, so a
// `//` never swallows a following fragment's code — the line stays valid C however many
// fragments collide. Each fragment's tag is derived from [line], its grid position.
class TargetLine(val line: Int) {
    val fragments = mutableListOf<Fragment>()

    fun isEmpty() = fragments.isEmpty()

    operator fun plusAssign(fragment: Fragment) {
        fragments += fragment
    }

    fun render(): String {
        if (fragments.isEmpty()) return ""
        // Decompiled code carries its provenance *in front of* the statement it belongs to, as a block
        // comment. A trailing `//` forced this class to emit every fragment's code before any
        // fragment's note, so a row holding several statements ended in a run of detached tags that
        // said nothing about which was which; and only the last one could carry a `//` at all without
        // commenting out its neighbours. In front, each statement names its own line, several can
        // share a row, and the row stays valid C. Repeats collapse: one marker per distinct line.
        var lastMark: String? = null
        val decomp = fragments.filter { it.shape == NoteShape.PROVENANCE && it.code != null }.map { f ->
            val mark = f.note?.takeIf { it != lastMark }?.also { lastMark = it }
            mark?.let { "/* ⇐ $it */ " }.orEmpty() + f.code
        }
        val rest = fragments.filterNot { it.shape == NoteShape.PROVENANCE && it.code != null }
        val code = spliceInlineMarkers((decomp + rest.mapNotNull { it.code }).joinToString("   "))
        // Deduped: every fragment on a row restates that row's line, so two typedefs sharing source
        // line 139 produced `typedef unsigned char _Value_type;   typedef Exclusion _Value_type;
        // // L 139 // L 139`. Only exact repeats collapse — `// L 139` and `// L 139 (param)` say
        // different things and both stay.
        val comments = rest.mapNotNull { it.commentAt(line) }.distinct().joinToString(" ")
        val body = when {
            code.isEmpty() -> comments
            comments.isEmpty() -> code
            else -> "$code  $comments"
        }
        // Indent to the shallowest code fragment — when a function opener (col 0) shares a line with an
        // indented global, the line starts at the opener, not the first-added fragment. Comment-only
        // fragments (a stray tag) don't pull the indent in.
        val indent = fragments.filter { it.code != null }.minOfOrNull { it.indent } ?: fragments.first().indent
        return " ".repeat(indent) + body
    }
}

// One [TargetLine] per 1-based source line (index 0 unused), so `canvas[n]` is where
// source line n renders.
class Canvas(val maxLine: Int) {
    private val lines = List(maxLine + 1) { TargetLine(it) }

    operator fun get(line: Int) = lines[line]

    fun multiFragmentLines() = lines.filter { it.fragments.size > 1 }

    // The last line worth rendering: trailing blank lines and lines carrying only
    // misattributed (stale N_SOL) fragments are noise past the file's real content.
    private fun lastMeaningfulLine() = (maxLine downTo 1).firstOrNull { line ->
        // Anything on the line counts. Trimming on a staleness flag once deleted `class bouniaf` and
        // its whole body from header.h the moment nothing happened to sit below it — a real
        // declaration lost to a heuristic about where gcc said it was.
        lines[line].fragments.isNotEmpty()
    } ?: 0

    /**
     * Strict alignment: source line n → output line n. [trim] cuts trailing blank and
     * stale-only lines (decomp mode); skeleton mode keeps the full source-aligned height.
     *
     * [compact] gives up literal alignment instead, collapsing every run of blank rows to one. It is
     * the default because alignment is mostly empty: 85% of the render is blank rows and
     * `bits/istream.tcc` spends 1,187 of them to show four lines of content (§33). Every row keeps
     * the `L n` its content was placed at, so the line a row came from survives the collapse even
     * though its position no longer encodes it.
     */
    fun render(trim: Boolean, compact: Boolean = false) = buildString {
        val last = if (trim) lastMeaningfulLine() else maxLine
        var blank = false
        for (line in 1..last) {
            val text = this@Canvas[line].render()
            if (compact && text.isBlank()) {
                if (!blank) append('\n')
                blank = true
            } else {
                append(text).append('\n')
                blank = text.isBlank()
            }
        }
    }

    override fun toString() = render(trim = false)
}
