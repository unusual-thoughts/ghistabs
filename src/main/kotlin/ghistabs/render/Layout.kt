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

// What a fragment represents, so the render step can pick its comment shape. Contention between
// kinds is settled by Owner before anything is written, so this no longer decides any fate.
enum class FragmentKind {
    SLINE,
    FUNC_DELIM,
    DECL_LOCAL,
    DECL_GLOBAL,
    TYPEDEF,
    TYPE_BODY,
    DECOMP,
    OTHER,
}

// One piece of a line, fully semantic: [code] is the C text (null for a bare comment),
// [note] the comment payload (a role, an address run, a delimiter phrase — null for a
// pure-code line). The line number the tag restates is the fragment's grid position, so
// the comment is derived at render time via [commentAt], not stored.
data class Fragment(
    val indent: Int = 0,
    val code: String? = null,
    val note: String? = null,
    val kind: FragmentKind = FragmentKind.OTHER,
    val stale: Boolean = false,
) {
    fun commentAt(line: Int) = note?.let { commentFor(line, kind, it, stale) }
}

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
        val decomp = fragments.filter { it.kind == FragmentKind.DECOMP && it.code != null }.map { f ->
            val mark = f.note?.takeIf { it != lastMark }?.also { lastMark = it }
            mark?.let { "/* ⇐ $it */ " }.orEmpty() + f.code
        }
        val rest = fragments.filterNot { it.kind == FragmentKind.DECOMP && it.code != null }
        val code = (decomp + rest.mapNotNull { it.code }).joinToString("   ")
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
        // Anything carrying code counts, misattributed or not. Trimming on `!stale` alone deleted
        // `class bouniaf` and its whole body from header.h the moment nothing happened to sit below
        // it — a real declaration lost to a heuristic about where gcc said it was.
        lines[line].fragments.any { !it.stale || it.code != null }
    } ?: 0

    /**
     * Strict alignment: source line n → output line n. [trim] cuts trailing blank and
     * stale-only lines (decomp mode); skeleton mode keeps the full source-aligned height.
     */
    fun render(trim: Boolean) = buildString {
        val last = if (trim) lastMeaningfulLine() else maxLine
        for (line in 1..last) append(this@Canvas[line].render()).append('\n')
    }

    override fun toString() = render(trim = false)
}
