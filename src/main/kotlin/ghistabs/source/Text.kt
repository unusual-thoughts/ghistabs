package ghistabs.source

/**
 * [text] with the contents of comments and literals replaced by spaces, every offset and every
 * newline where it was — so a `{` in the result is a `{` in the code and the line it sits on is
 * still the file's. libstdc++ has braces in comments and `"{"` in literals, and either one closes a
 * body that never opened.
 *
 * Line continuations count: a `//` comment and a literal both run past a backslash-newline.
 */
fun scannable(text: String): CharArray {
    val out = text.toCharArray()
    var i = 0
    while (i < out.size) {
        i = when {
            out.startsAt(i, "//") -> out.blank(i, out.lineEnd(i))
            out.startsAt(i, "/*") -> out.blank(i, out.past("*/", i + 2))
            out[i] == '"' || out[i] == '\'' -> out.blank(i, out.literalEnd(i))
            else -> i + 1
        }
    }
    return out
}

/** Space out `[from, to)`, keeping newlines. Returns [to], so it reads as a cursor move. */
private fun CharArray.blank(from: Int, to: Int): Int {
    (from until to).forEach { if (this[it] != '\n') this[it] = ' ' }
    return to
}

private fun CharArray.startsAt(i: Int, s: String) = i + s.length <= size && s.indices.all { this[i + it] == s[it] }

/** Just past [s], or the end of the text when it never comes — an unterminated comment. */
private fun CharArray.past(s: String, from: Int) =
    (from..size - s.length).firstOrNull { startsAt(it, s) }?.plus(s.length) ?: size

/** The newline ending the logical line [i] is on, backslash continuations followed. */
private tailrec fun CharArray.lineEnd(i: Int): Int {
    val nl = (i until size).firstOrNull { this[it] == '\n' } ?: return size
    return if (continued(nl)) lineEnd(nl + 1) else nl
}

private fun CharArray.continued(newline: Int) =
    (newline - 1).let { if (it >= 0 && this[it] == '\r') it - 1 else it }.let { it >= 0 && this[it] == '\\' }

/** Just past the closing quote; at an unterminated literal, the end of its line rather than the file. */
private fun CharArray.literalEnd(start: Int): Int {
    var i = start + 1
    while (i < size) {
        when {
            this[i] == '\\' -> i++
            this[i] == this[start] -> return i + 1
            this[i] == '\n' && !continued(i) -> return i
        }
        i++
    }
    return size
}
