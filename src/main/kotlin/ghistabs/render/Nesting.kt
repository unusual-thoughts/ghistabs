package ghistabs.render

/**
 * Braces to prepend and to append so a run of rows comes out *well-nested*, not merely balanced.
 *
 * A net count cannot see order. A stretch beginning `} else {` nets zero and reads as balanced while
 * the `if (…) {` it closes sits in another file's view; a stretch that closes two blocks and reopens
 * two nets zero the same way, and renders as a function ending before its last statements. What
 * decides both ends is the running depth's low-water mark: that many openers are missing in front,
 * and whatever the run then ends on has to be closed.
 *
 * Fed each row's brace *tokens*, not its characters — a `{` in a string literal is not a block.
 */
fun braceFix(braces: Sequence<Char>): Pair<Int, Int> = braces
    .fold(0 to 0) { (depth, low), c ->
        when (c) {
            '{' -> depth + 1 to low
            '}' -> depth - 1 to minOf(low, depth - 1)
            else -> depth to low
        }
    }
    .let { (depth, low) -> -low to depth - low }

/**
 * The row each of [anchors] may not render above: the row the region before it took, starting at
 * [floor]. Nothing may rise above what precedes it, so the rendered rows come out in the order the
 * decompiler wrote them however the anchors are ordered.
 *
 * Anchors run backwards wherever gcc attributes a statement to the line its *expression* was written
 * on rather than the line it executes at, which is every loop (the condition carries the `for` line,
 * above the body it follows) and every block whose opener is a later line than its contents. Placed
 * at those anchors, `Integer::IsConvertableToLong` put `if (sign == POSITIVE) {` at integer.cpp L2805
 * *below* both of its branches at L2803, so L2802-3 ran inside a block nothing had opened.
 *
 * Weaker rules were tried and are not enough. Holding a region below its enclosing opener, and a
 * closing region below what its block holds, covers those two cases and still lets a *sibling* block
 * invert: an `if (y) {` anchored earlier than the `if (x) { … }` before it sorts above the lot and
 * ends up wrapping it — balanced, never negative, and the clauses inverted. Total order is what rules
 * that out, because the decompiler's order is the structure.
 *
 * The cost is alignment, and it is charged to the loops: a body's tail sinks to wherever its
 * predecessors left off rather than returning to the `for` line. Deliberate — a statement one row
 * from where gcc put it still reads, a statement in the wrong block does not.
 */
fun nestingRows(anchors: List<Int?>, floor: Int) =
    anchors.runningFold(floor) { above, anchor -> maxOf(above, anchor ?: above) }.drop(1)

/** Cumulative brace depth after each row; index 0 is the depth before the first row. */
fun braceDepths(rows: List<String>) =
    rows.runningFold(0) { depth, row -> depth + row.count { it == '{' } - row.count { it == '}' } }

/**
 * Functions whose rendered nesting had not returned to the level they opened at by the time the next
 * function opens — the invariant a `{` vs `}` count per file cannot state. The body slid that far and
 * carries its closer with it, so everything it passed is nested inside it: image.cpp ran `operator[]`
 * from L41 to L128 with three accessors inside it while every count in the file balanced.
 *
 * Not judged against [FunctionSpans.closeLine] exactly: a body may borrow the blank rows below its
 * span when it outgrows it, and a crammed one closes on its own opener, so a close a row or two off
 * the span is slack the layout grants rather than a defect.
 *
 * The mirror case — a function closing *early*, over rows of its own still rendered below — is not
 * stated here. It needs to know which rows are the function's, which rendered text cannot say: in a
 * header the rows between two openers belong to neither, so reading them as body reported every
 * crammed one-row function in the corpus.
 */
fun FunctionSpans.closeAnomalies(rows: List<String>): List<String> {
    val depth = braceDepths(rows)
    val openers = ranges.map { it.start }
    return ranges.mapNotNull { range ->
        val expected = with(this) { range.closeLine } ?: return@mapNotNull null
        val outer = depth.getOrNull(range.start - 1) ?: return@mapNotNull null
        val next = openers.filter { it > range.start }.minOrNull() ?: return@mapNotNull null
        if ((range.start..<next).any { (depth.getOrNull(it) ?: outer) <= outer }) {
            null
        } else {
            "function ${range.func.demangledName} opens at L${range.start} and is still open where " +
                "the next one opens at L$next (span says it closes at L$expected)"
        }
    }
}
