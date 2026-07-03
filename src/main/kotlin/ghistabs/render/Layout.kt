package ghistabs.render

/**
 * Start row for each ordered block sized [sizes] in `start+1..end`. When the blocks all fit they get
 * their full size with the leftover height spread as even gaps between them (so a big trailing block —
 * a run of closing braces — isn't stranded and the body fills the span); when they don't, each gets a
 * share of the room proportional to its size (at least one row) so no block is starved to a single
 * crammed line while others expand. A block that still overruns [end] butts against it.
 */
fun spreadBlocks(start: Int, end: Int, sizes: List<Int>): List<Int> {
    if (sizes.isEmpty()) return emptyList()
    val room = end - start
    val total = sizes.sum()
    val alloc = if (total <= room) sizes else sizes.map { (it.toLong() * room / total).toInt().coerceAtLeast(1) }
    val slack = (room - alloc.sum()).coerceAtLeast(0)
    var row = start
    return alloc.mapIndexed { i, a ->
        row += slack * (i + 1) / alloc.size - slack * i / alloc.size
        (row + 1).coerceAtMost(end).also { row += a }
    }
}

/**
 * Break a long decompiler statement across rows at its top-level `&&`/`||` boundaries, so a crammed
 * `if` condition (Ghidra wraps then §9 rejoins onto one 300-char row) spreads into blank rows instead.
 * Paren/bracket depth is tracked so a boolean operator inside a call's args never splits; the operator
 * stays at the end of its row (K&R), continuations sit one step past [depth]. Recurses so each piece
 * falls under [minLen] where its own shallower boundaries allow; a short line, or one with no top-level
 * operator, stays a single row.
 */
fun wrapDecompLine(text: String, depth: Int, minLen: Int = 120): List<Pair<Int, String>> =
    splitCondition(text, minLen).mapIndexed { i, s -> (if (i == 0) depth else depth + 2) to s }

private fun splitCondition(text: String, minLen: Int): List<String> {
    if (text.length <= minLen) return listOf(text)
    val cuts = topLevelBooleanCuts(text)
    if (cuts.isEmpty()) return listOf(text)
    val pieces = buildList {
        var prev = 0
        for (c in cuts) {
            add(text.substring(prev, c).trim())
            prev = c
        }
        add(text.substring(prev).trim())
    }
    return pieces.flatMap { splitCondition(it, minLen) }
}

// Indices just past each shallowest-depth ` && `/` || ` in [text] — the top-level boolean joins,
// the readable split points. Empty when the line has none at any depth.
private fun topLevelBooleanCuts(text: String): List<Int> {
    val cuts = mutableListOf<Pair<Int, Int>>()
    var depth = 0
    var i = 0
    while (i < text.length) {
        when (text[i]) {
            '(', '[' -> depth++
            ')', ']' -> depth--
        }
        if (text[i] == ' ' &&
            i + 3 < text.length &&
            (text.regionMatches(i + 1, "&& ", 0, 3) || text.regionMatches(i + 1, "|| ", 0, 3))
        ) {
            cuts += (i + 4) to depth
            i += 4
        } else {
            i++
        }
    }
    val minDepth = cuts.minOfOrNull { it.second } ?: return emptyList()
    return cuts.filter { it.second == minDepth }.map { it.first }
}

// Pure layout model: Canvas ⊃ TargetLine ⊃ Fragment.

// What a fragment represents, so the decompilation overlay can decide its fate from the
// tag and the render step can pick its comment shape. subsumedByDecomp covers everything
// the decomp already shows — brace delimiters, SLINE annotations, param/local decls.
enum class FragmentKind {
    SLINE,
    FUNC_DELIM,
    DECL_LOCAL,
    DECL_GLOBAL,
    TYPEDEF,
    TYPE_BODY,
    DECOMP,
    STRAY,
    OTHER,
    ;

    val subsumedByDecomp get() = this == SLINE || this == FUNC_DELIM || this == DECL_LOCAL
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

    // Free for a brace block to expand into: empty, or holding only misattributed (stale
    // N_SOL) fragments, which legitimate content may evict rather than fold around.
    fun isExpandable() = fragments.all { it.stale }

    operator fun plusAssign(fragment: Fragment) {
        fragments += fragment
    }

    fun render(): String {
        if (fragments.isEmpty()) return ""
        val code = fragments.mapNotNull { it.code }.joinToString("   ")
        val comments = fragments.mapNotNull { it.commentAt(line) }.joinToString(" ")
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

    private fun blankRunFrom(line: Int) = lines.drop(line).takeWhile { it.isExpandable() }.count()

    /**
     * Spread a brace block into the expandable lines at and below [line]: [open] on [line], one
     * [items] entry per line, then [close] — the item/close fragments inheriting [open]'s
     * indent (+4), kind and staleness. A short run crams leftover items + [close] onto the
     * last line; no room folds the lot onto [line] (tag kept on [open] so no code is lost).
     * Items arrive already punctuated; cramming just space-joins them. Writing a line evicts
     * any misattributed (stale) fragment so a lone stale decl can't force the fold.
     */
    fun layoutBraceBlock(line: Int, open: Fragment, items: List<String>, close: String) {
        val available = blankRunFrom(line)
        fun code(indent: Int, text: String) = Fragment(indent, text, kind = open.kind, stale = open.stale)
        fun place(target: Int, fragment: Fragment) {
            this[target].fragments.removeAll { it.stale }
            this[target] += fragment
        }
        val inner = open.indent + 4
        when {
            available >= items.size + 2 -> {
                place(line, open)
                items.forEachIndexed { i, s -> place(line + 1 + i, code(inner, s)) }
                place(line + 1 + items.size, code(open.indent, close))
            }

            available > 1 -> {
                place(line, open)
                val belowSlots = available - 1
                val onePerLine = belowSlots - 1
                for (i in 0 until onePerLine) place(line + 1 + i, code(inner, items[i]))
                place(line + belowSlots, code(inner, "${items.drop(onePerLine).joinToString(" ")} $close"))
            }

            else -> place(line, open.copy(code = "${open.code} ${items.joinToString(" ")} $close"))
        }
    }

    // The last line worth rendering: trailing blank lines and lines carrying only
    // misattributed (stale N_SOL) fragments are noise past the file's real content.
    private fun lastMeaningfulLine() = (maxLine downTo 1).firstOrNull { line ->
        lines[line].fragments.any { !it.stale }
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
