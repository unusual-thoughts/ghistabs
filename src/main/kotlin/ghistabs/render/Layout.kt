package ghistabs.render

// Pure layout model: Canvas ⊃ TargetLine ⊃ Fragment.

// One piece of a line: source [code] and its provenance [comment] kept apart so
// decompilation can drop the comment or replace the code without string-surgery.
// Comment-only = a bare SLINE annotation; code-only = e.g. a decomp line.
data class Fragment(val indent: String = "", val code: String? = null, val comment: String? = null) {
    val isSlineAnnotation get() = code == null && comment != null
    val isFuncDelim get() = comment?.let { "— opens " in it || "— closes " in it || "out-of-line inline decl" in it } ==
        true
}

// The fragments sharing one source line. Renders all code first, all comments last,
// so a `//` never swallows a following fragment's code — the line stays valid C
// however many fragments collide.
class TargetLine {
    val fragments = mutableListOf<Fragment>()

    fun isEmpty() = fragments.isEmpty()

    operator fun plusAssign(fragment: Fragment) {
        fragments += fragment
    }

    override fun toString(): String {
        if (fragments.isEmpty()) return ""
        val code = fragments.mapNotNull { it.code }.joinToString("   ")
        val comments = fragments.mapNotNull { it.comment }.joinToString(" ")
        val body = when {
            code.isEmpty() -> comments
            comments.isEmpty() -> code
            else -> "$code  $comments"
        }
        return fragments.first().indent + body
    }
}

// One [TargetLine] per 1-based source line (index 0 unused), so `canvas[n]` is where
// source line n renders.
class Canvas(val maxLine: Int) {
    private val lines = List(maxLine + 1) { TargetLine() }

    operator fun get(line: Int) = lines[line]

    fun multiFragmentLines() = lines.filter { it.fragments.size > 1 }

    private fun blankRunFrom(line: Int) = lines.drop(line).takeWhile { it.isEmpty() }.count()

    /**
     * Spread a brace block into the blank lines at and below [line]: open line, one
     * [item][items] per line, then [close]. A short run crams the leftover items +
     * [close] onto the last line; no room folds the lot onto [line] with the tag in the
     * comment field so no code is lost.
     */
    fun layoutBraceBlock(
        line: Int,
        indent: String,
        openCode: String,
        openComment: String?,
        items: List<String>,
        close: String,
        itemSuffix: String,
        sep: String,
    ) {
        val available = blankRunFrom(line)
        val inner = "$indent    "
        fun item(i: Int) = Fragment(inner, code = "${items[i]}$itemSuffix")
        val open = Fragment(indent, openCode, openComment)
        when {
            available >= items.size + 2 -> {
                this[line] += open
                items.indices.forEach { this[line + 1 + it] += item(it) }
                this[line + 1 + items.size] += Fragment(indent, code = close)
            }

            available > 1 -> {
                this[line] += open
                val belowSlots = available - 1
                val onePerLine = belowSlots - 1
                for (i in 0 until onePerLine) this[line + 1 + i] += item(i)
                val overflow = items.drop(onePerLine).joinToString(sep)
                this[line + belowSlots] += Fragment(inner, code = "$overflow $close")
            }

            else -> this[line] +=
                Fragment(indent, code = "$openCode ${items.joinToString(sep)} $close", comment = openComment)
        }
    }

    /** Strict alignment: source line n → output line n, blank where empty. */
    override fun toString() = buildString {
        for (line in 1..maxLine) append(this@Canvas[line]).append('\n')
    }
}
