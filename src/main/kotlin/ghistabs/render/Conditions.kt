package ghistabs.render

/**
 * The condition of an `if (…) {` that opens a block at the end of [text], as a range within it.
 *
 * Found by walking the parens back from the `{`, not by pattern: a row carries several statements
 * here (the folded head, rejoined continuations), and a greedy `if \((.*)\) \{` on
 * `… { if (a != false) { if (b == c) {` spans from the first `if` to the last brace, so negating it
 * spliced the parens around two conditions and one `{` — `if (!(a != false) { if (b`, a paren short.
 */
private fun ifConditionAt(text: String): IntRange? {
    if (!text.endsWith("{")) return null
    val close = text.dropLast(1).indexOfLast { !it.isWhitespace() }.takeIf { it > 0 && text[it] == ')' } ?: return null
    var depth = 0
    for (i in close downTo 0) {
        when (text[i]) {
            ')' -> depth++
            '(' -> depth--
        }
        if (depth != 0) continue
        return if (text.take(i).trimEnd().endsWith("if")) (i + 1)..<close else null
    }
    return null
}

// Ghidra breaks a branch across two lines, `}` then `else {`, and they are not continuations of each
// other (equal indent), so they arrive as two DecompLines. The one-line spelling shows up only where
// something upstream has already joined them.
private const val ELSE_INLINE = "} else {"
private const val ELSE_OPEN = "else {"

/**
 * Put an `if`/`else` back the way round the source had it, negating the condition to match.
 *
 * Ghidra picks whichever sense of a branch its own analysis reached, which is regularly the opposite
 * of what was written: `if (ByteCount() > sizeof(long)) return false;` comes back as
 * `if (uVar1 < 5) { …the whole rest of the function… } else { local_c = false; }`. Structurally
 * sound, faithful to the binary, and backwards to read.
 *
 * Which way round the source had it is not guessed from the shape — gcc's line table says so. Every
 * line carries the address its tokens came from, so each branch has a lowest source line, and the
 * branch the source wrote first is the one with the lower. `IsConvertableToLong`'s else-branch
 * anchors at integer.cpp L2800 against the then-branch's L2802, so the source's condition was this
 * one's negation.
 *
 * Swapping also pays back placement: the lower-anchored branch moves first, so its rows stop being
 * held below the higher-anchored ones by [nestingRows].
 *
 * Spelled `!(…)` rather than by flipping the comparison — sound whatever the condition is, where
 * `<` → `>=` holds only for a bare relational one. `else if` chains are left alone: the separator has
 * to be exactly `} else {`, so a chain's second condition can't be stranded under a negated first.
 */
fun List<DecompLine>.uninvertConditions(sourceLine: (DecompLine) -> Int?): List<DecompLine> {
    val lines = toMutableList()
    for (open in indices) {
        val text = lines[open].text.trimEnd()
        val condition = ifConditionAt(text) ?: continue
        val (separator, close) = lines.branchesOf(open) ?: continue
        val then = lines.subList(open + 1, separator.first).toList()
        val otherwise = lines.subList(separator.last + 1, close).toList()
        val first = { branch: List<DecompLine> -> branch.mapNotNull(sourceLine).minOrNull() }
        val (thenAt, elseAt) = first(then) to first(otherwise)
        if (thenAt == null || elseAt == null || elseAt >= thenAt) continue
        val negated = text.replaceRange(condition, "!(${text.substring(condition)})")
        lines[open] = lines[open].copy(text = negated)
        val kept = separator.map { lines[it] }
        (otherwise + kept + then).forEachIndexed { i, line -> lines[open + 1 + i] = line }
    }
    return lines
}

/**
 * The rows separating the two branches of the `if` opened at [open], and the `}` that closes the
 * second — null where it has no `else`, or where the `else` carries its own `if`. Found by brace
 * depth, so a nested `if`/`else` inside either branch is stepped over rather than mistaken for this
 * one's separator.
 */
private fun List<DecompLine>.branchesOf(open: Int): Pair<IntRange, Int>? {
    var depth = 1
    for (i in open + 1..lastIndex) {
        val text = this[i].text.trim()
        // The one-line spelling closes and reopens on the same row, so it never reaches depth 0.
        if (depth == 1 && text == ELSE_INLINE) return closeOf(i + 1)?.let { i..i to it }
        depth += this[i].delta()
        if (depth == 0) {
            if (text != "}" || getOrNull(i + 1)?.text?.trim() != ELSE_OPEN) return null
            return closeOf(i + 2)?.let { i..i + 1 to it }
        }
    }
    return null
}

/** Index of the `}` closing a block whose body starts at [from]. */
private fun List<DecompLine>.closeOf(from: Int): Int? {
    var depth = 1
    for (i in from..lastIndex) {
        depth += this[i].delta()
        if (depth == 0) return i
    }
    return null
}

private fun DecompLine.delta() = text.count { it == '{' } - text.count { it == '}' }
