package ghistabs.render

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
 * `<` → `>=` holds only for a bare relational one. Which rows are which branch, and whether there is
 * a plain `else` at all, come from [DecompLine.branches]: the groups `printc.cc` wrapped each branch
 * in. `else if` chains have no such pair, so a chain's second condition can't be stranded under a
 * negated first.
 */
fun List<DecompLine>.uninvertConditions(sourceLine: (DecompLine) -> Int?): List<DecompLine> {
    val lines = toMutableList()
    // Innermost first. A swap moves whole branch blocks, so an enclosing `if`'s extents survive a
    // nested one's swap while the reverse is not true. The decisions themselves don't depend on the
    // order — each reads only its branches' source lines, which no swap changes.
    for (open in indices.reversed()) {
        val line = lines[open]
        val condition = line.ifCondition ?: continue
        val (then, otherwise) = line.branches ?: continue
        val first = { rows: IntRange -> rows.mapNotNull { sourceLine(lines[it]) }.minOrNull() }
        val thenAt = first(then) ?: continue
        val elseAt = first(otherwise) ?: continue
        if (elseAt >= thenAt) continue
        lines[open] = line.negate(condition)
        // The rows between the branches — the `}`, the `else {` — stay between them.
        val separator = ((then.last + 1)..<otherwise.first).map { lines[it] }
        val swapped = otherwise.map { lines[it] } + separator + then.map { lines[it] }
        swapped.forEachIndexed { i, l -> lines[then.first + i] = l }
    }
    return lines
}
