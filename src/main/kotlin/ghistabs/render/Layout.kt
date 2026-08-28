package ghistabs.render

import ghistabs.harvest.Type

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
    val piece = { r: IntRange -> text.substring(r.first, r.last + 1).trim() }
    if (span.last - span.first + 1 <= minLen) return listOf(piece(span))
    // Shallowest first, and only within this piece: a nested boundary is a split point for the piece
    // it ends up in, not for this one.
    val inside = cuts.filter { it.at > span.first && it.at <= span.last }
    val top = inside.minOfOrNull { it.depth } ?: return listOf(piece(span))
    val at = inside.filter { it.depth == top }.map { it.at }
    val spans = (listOf(span.first) + at).zipWithNext { a, b -> a..<b } + listOf(at.last()..span.last)
    return spans.flatMap { splitCondition(text, it, cuts, minLen) }
}

// "L  17" — the source-line reference stamped on every tag.
private fun lineRef(line: Int) = "L" + line.toString().padStart(4)

/**
 * How a row's [note] is spelled once it reaches the page.
 *
 * Four cases, because four is how many the rendered text actually distinguishes. The `FragmentKind`
 * this replaces had eight, five of which ([DECLARATION]'s) produced the same comment — a distinction
 * that existed only to be mapped back from [Owner], and had to be kept in step with it for no gain.
 */
enum class NoteShape {
    /** An N_SLINE address annotation: which instructions the line compiled to. */
    SLINE,

    /** A function's opening or closing brace, naming what it delimits. */
    DELIMITER,

    /**
     * Which source line a decompiled statement's instructions came from. Reaches [commentFor] only
     * for a row with no code of its own; where there is code the marker goes in *front* of it, which
     * [TargetLine.render] does because collapsing repeats needs the whole row.
     */
    PROVENANCE,

    /** A declaration's provenance tag, carrying its role — the shape everything else takes. */
    DECLARATION,
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
    /**
     * The trailing comment for a fragment carrying [note] at [line], shaped by [shape]. A [DECLARATION]
     * tag's [note] is the role: empty for a typedef or type body, "(param)" and the like for a decl.
     */
    fun commentAt(line: Int) = when (shape) {
        else if note == null -> null
        NoteShape.SLINE -> "// ${lineRef(line)} @ $note"
        NoteShape.DELIMITER -> "/* ${lineRef(line)} — $note */"
        NoteShape.PROVENANCE -> "// ⇐ $note"
        NoteShape.DECLARATION -> "// ${lineRef(line)}" + if (note.isEmpty()) "" else " $note"
    }
}

// An empty block and the markers naming what was inlined out of it: `for (…) { }` followed by
// `/* ⇐ inlines stl_vector.h L 123 */`, or by the pseudo-call that stands in for it. That call is
// recognised by the shape both spellings share — a `__` join and the source line it ends with, as in
// `__inline_stl_vector_h_123` and `_M_deallocate__stl_vector_h_123` — since with a source root the
// `__inline_` prefix is only what an unnamed stretch falls back to. Both halves are needed:
// `FUN_00401234()` ends in digits and `__cxa_end_catch()` has the join.
private val EMPTY_BLOCK_MARKERS =
    Regex("""\{ *\}((?: *(?:/\* ⇐ inlines[^*]*\*/|(?:\w+ = )?\w*__\w+_\d+\([^()]*\);))+)""")

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

// One [TargetLine] per 1-based source line, so `canvas[n]` is where source line n renders.
class Canvas(maxLine: Int?) : ClosedRange<Int> {
    override val start = 1
    override val endInclusive = maxLine ?: 0
    private val lines = maxLine?.let { n -> List(n) { TargetLine(it + 1) } }.orEmpty()

    operator fun get(line: Int) = lines[line - 1]

    fun multiFragmentLines() = lines.filter { it.fragments.size > 1 }

    // The last line worth rendering: trailing blank lines and lines carrying only
    // misattributed (stale N_SOL) fragments are noise past the file's real content.
    private val lastMeaningfulLine by lazy {
        lines.lastOrNull {
            // Anything on the line counts. Trimming on a staleness flag once deleted `class XVImage` and
            // its whole body from xvimage.h the moment nothing happened to sit below it — a real
            // declaration lost to a heuristic about where gcc said it was.
            it.fragments.isNotEmpty()
        }?.line
    }

    // No meaningful line at all means every row is past the content, not that none is: a canvas
    // holding nothing trims to nothing, which is what `1..0` used to say.
    private fun TargetLine.needsTrimming() = line.beyond(lastMeaningfulLine)

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
        var blank = false
        for (line in lines) {
            if (trim && line.needsTrimming()) {
                break
            }
            val text = line.render()
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

/** The furthest line anything attests to, or null where nothing does — never a zero standing in. */
internal fun extentOf(vararg lines: Int?) = lines.filterNotNull().maxOrNull()

/**
 * Past an extent, where a file that reaches nothing is reached past by everything: the extents are
 * what a line is judged against, and "no evidence" was the case that judged every line stale before
 * they could be null. A null [this] is no line at all, so it is past nothing.
 */
internal fun Int?.beyond(extent: Int?) = this != null && (extent == null || this > extent)

/** One stabs variable of a function, declared in this file: where gcc put it and how it renders. */
data class Var(val line: Int?, val name: String, val text: String, val role: String?) {
    fun declKey() = line?.let { Type.Decl(it, name) }
}
