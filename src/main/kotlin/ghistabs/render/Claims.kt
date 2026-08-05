package ghistabs.render

/**
 * Space allocation for the line-aligned canvas: passes declare what they want, one allocator decides
 * who gets which rows. See `docs/design-plans/layout-rewrite.md`.
 *
 * The split this enforces is that **the allocator assigns space and the renderer fits content into
 * it**. Cramming, wrapping and spreading are the renderer's business; all that happens here is
 * answering "which rows does this claim get". Conflating the two is what produced a placement routine
 * that had to know about brace formatting and a sweep that had to un-place what an earlier pass wrote.
 */

/** How much room a claim can use beyond the rows it brings. */
enum class Fit {
    /** Exactly its own rows. A typedef is one row at one line or it is nowhere. */
    RIGID,

    /**
     * Its own rows, then whatever is still free below before the next claim. An initializer knows
     * where it starts and not where it ends — a big array, a struct body, a decompiled statement run.
     */
    ELASTIC,
}

/**
 * Who is claiming, in priority order: the earlier entry wins a genuinely contested row. Ordered by
 * what a reader came for, which is not the same axis as [Fit] — see the allocator's ordering.
 */
enum class Owner {
    FUNCTION_BODY,
    GLOBAL,
    TYPE_BODY,
    TYPEDEF,
    INCLUDE,
}

/** One rendered row: its text and the column it starts at. Provenance is the renderer's to add. */
data class Row(val text: String, val indent: Int = 0)

/**
 * A pass's request for space. [line] is the source line the content belongs to, null to float in the
 * band above the first anchored row (an `#include`, which belongs to the file rather than a line).
 */
data class Claim(val owner: Owner, val line: Int?, val rows: List<Row>, val fit: Fit = Fit.RIGID)

/** [claim] got [range]; [copies] > 1 when identical claims merged. */
data class Placement(val claim: Claim, val range: IntRange, val copies: Int = 1)

/** [claim] got nothing, because [reason]. Rendered as a trace unless suppressed, always counted. */
data class Dropped(val claim: Claim, val reason: String)

/** Every claim accounted for: `placed.size + dropped.size` covers the input, after merging. */
data class Allocation(val placed: List<Placement>, val dropped: List<Dropped>)

private const val ROW_TAKEN = "line already taken"
private const val NO_ROOM = "no free row in the band"

/**
 * Assign rows in `1..maxLine` to [claims].
 *
 * The two axes the design settles on are separate concerns, and collapsing them into one sort gets
 * the wrong answer: [Owner] decides **who wins a contested row**, [Fit] decides **how far a winner
 * may spread**. Sorting by rigidity first instead makes a one-row claim beat a higher-priority
 * elastic one outright, so a type body gcc misfiled into a function's span evicts the function.
 *
 * So, two phases. **Reserve**, in priority order: each claim gets its own line or nothing, which
 * settles every genuine conflict by importance alone. **Expand**, in the same order: a winner grows
 * downward through rows nobody reserved — a rigid claim up to the rows it brought, an elastic one
 * until it meets the next reservation. A typedef therefore keeps its line under an expanding
 * initializer without having to outrank it, because it reserved that row in phase one.
 *
 * Identical claims merge before either phase: two claims for the same line with the same rows *are*
 * the same claim, which is where the `×N` inlined-copy count comes from.
 */
fun allocate(claims: List<Claim>, maxLine: Int): Allocation {
    val merged = claims
        .groupBy { Triple(it.owner, it.line, it.rows) }
        .map { (_, same) -> same.first() to same.size }

    val order = compareBy<Pair<Claim, Int>>({ it.first.owner.ordinal }, { it.first.line ?: Int.MAX_VALUE })

    val held = mutableSetOf<Int>()
    val placed = mutableListOf<Placement>()
    val dropped = mutableListOf<Dropped>()

    // Anchored first — floating claims fill what is left of the band above them, so they need to know
    // where the content starts.
    val (anchored, floating) = merged.sortedWith(order).partition { it.first.line != null }

    val reserved = anchored.mapNotNull { (claim, copies) ->
        val line = claim.line ?: return@mapNotNull null
        if (line !in 1..maxLine || !held.add(line)) {
            dropped += Dropped(claim, ROW_TAKEN)
            null
        } else {
            Triple(claim, copies, line)
        }
    }

    for ((claim, copies, line) in reserved) {
        val wanted = if (claim.fit == Fit.RIGID) claim.rows.size else maxLine - line + 1
        val end = (line + 1 until line + wanted).takeWhile { it <= maxLine && it !in held }.lastOrNull() ?: line
        held += line..end
        placed += Placement(claim, line..end, copies)
    }

    // The band above the first anchored row, one floating claim per row, in priority order.
    var next = 1
    val firstAnchored = placed.minOfOrNull { it.range.first } ?: (maxLine + 1)
    for ((claim, copies) in floating) {
        val row = (next until firstAnchored).firstOrNull { it !in held }
        if (row == null) {
            dropped += Dropped(claim, NO_ROOM)
            continue
        }
        val end = (row until row + claim.rows.size).takeWhile { it < firstAnchored && it !in held }.last()
        held += row..end
        placed += Placement(claim, row..end, copies)
        next = end + 1
    }

    return Allocation(placed, dropped)
}
