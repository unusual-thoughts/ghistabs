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
    /** Decompiled statements. Outranks everything: in decomp mode it is what the reader came for. */
    FUNCTION_BODY,

    /**
     * The `sig {` / `}` a skeleton draws round a function. Ranked just under the body so that where
     * decompilation exists it takes the row and these drop — which is the retroactive
     * `subsumedByDecomp` sweep expressed as priority instead. Where it doesn't, they render.
     */
    FUNC_DELIM,
    GLOBAL,
    LOCAL,
    TYPE_BODY,
    TYPEDEF,

    /**
     * Compiler-generated data — `_ZTI` typeinfo objects, `_ZTS` typeinfo-name strings. Ranked under
     * every real declaration because none of it has a source line of its own: a typeinfo carries its
     * *class's* line (§38), so filing it where the class is declared — which is right — puts it on the
     * row the class body is rendering, and as a peer it crushed `class Image`'s twenty members onto
     * one line. It is its own [group] for the same reason: sharing is what did the damage.
     */
    GENERATED,

    /**
     * Code this file was inlined *into* somewhere else — the second decomp pass. Ranked below the
     * file's own declarations, unlike [FUNCTION_BODY]: in a header the declarations *are* the
     * content and the inlined fragments are incidental. Ranking them together evicted
     * `class XVImage` from xvimage.h in favour of statements from another file's function.
     */
    INLINED_BODY,
    INCLUDE,
    ;

    /**
     * Who counts as a peer. Exclusivity is between a *body* and a *declaration* — that contest is
     * the point, and losing it is what used to demote a declaration into a `// stray:` comment.
     * Declarations among themselves are not in contest at all: a typedef and a global really can sit
     * on one source line, they stacked there before one allocator resolved the whole file, and making
     * them fight cost 807 code tokens of skeleton output.
     */
    val group get() = when (this) {
        FUNCTION_BODY, INLINED_BODY -> "body"
        INCLUDE -> "include"
        GENERATED -> "generated"
        else -> "declaration"
    }

    /**
     * How this owner's rows spell their note. Three cases rather than one per owner: every
     * declaration-ish owner renders the same tag, and saying so here is what stops the mapping
     * drifting out of step with the shapes.
     */
    val noteShape get() = when (this) {
        FUNCTION_BODY, INLINED_BODY -> NoteShape.PROVENANCE
        FUNC_DELIM -> NoteShape.DELIMITER
        else -> NoteShape.DECLARATION
    }
}

/**
 * What a claim wants done when the row it asked for is already held. These are not variations on one
 * rule — they are three kinds of content:
 *
 * - [EXACT] — a declaration is at its line or it is nowhere. Sharing with a peer is fine; losing to
 *   another owner is a contest, because a declaration two rows from where gcc put it is a lie.
 * - [AFTER] — a decompiled statement takes the next free row instead. Ghidra revisits a source line
 *   (47 of 186 anchors in `xvimage.cpp` are claimed twice) and the second visit is real code that has
 *   to go somewhere; sharing would cram it onto the first. With no line at all it simply follows what
 *   came before — an inlined-region marker riding its call site.
 * - [BAND] — an `#include` belongs to the file rather than a line, and lands in the room above the
 *   content.
 */
enum class Anchoring { EXACT, AFTER, BAND }

/**
 * One rendered row: its text, the column it starts at, and any *role* annotation — `(param)`,
 * `(.bss static)`, the address run behind an N_SLINE. Line provenance is not here: the renderer adds
 * that from the row the allocator gave, which is the point of front-positioning it.
 */
data class Row(
    val text: String,
    val indent: Int = 0,
    val note: String? = null,
    // Where an over-long row may be broken, read from its tokens rather than found again in its
    // characters. Empty for a row nothing decompiled, which is never long enough to want breaking.
    val cuts: List<Cut> = emptyList(),
)

/**
 * A pass's request for space. [line] is the source line the content belongs to, null to float in the
 * band above the first anchored row (an `#include`, which belongs to the file rather than a line).
 *
 * [stale] marks a claim gcc misattributed — a declLine past the file's activity extent, a typedef
 * splayed across bogus lines by N_SOL. It loses every contested row, so a misattributed declaration
 * can no longer evict a real one; alone on its line it still renders, flagged.
 */
data class Claim(
    val owner: Owner,
    val line: Int?,
    val rows: List<Row>,
    val fit: Fit = Fit.RIGID,
    val stale: Boolean = false,
    val anchoring: Anchoring = if (line == null) Anchoring.BAND else Anchoring.EXACT,
    /** Furthest row an [Anchoring.AFTER] claim may slide to — a function body stays in its span. */
    val limit: Int? = null,
)

/** [claim] got [range]; [copies] > 1 when identical claims merged. */
data class Placement(val claim: Claim, val range: IntRange, val copies: Int = 1)

/** [claim] got nothing, because [reason]. Rendered as a trace unless suppressed, always counted. */
data class Dropped(val claim: Claim, val reason: String)

/** Every claim accounted for: `placed.size + dropped.size` covers the input, after merging. */
data class Allocation(val placed: List<Placement>, val dropped: List<Dropped>)

const val ROW_TAKEN = "line already taken"
const val NO_ROOM = "no free row in the band"
const val INSIDE_BODY = "line inside a function body"
const val CONFLICTED_DECL = "this line is claimed by several files"
const val FOREIGN_RUN = "run crosses this file's code"
const val OFF_CANVAS = "line outside the file"
const val MISATTRIBUTED = "stale N_SOL"

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
 * Two merges happen before either phase, and they are different things:
 *
 * - **Identical** claims collapse to one carrying a multiplicity — same line, same owner, same rows
 *   *are* the same claim, which is where the `×N` inlined-copy count comes from.
 * - **Peer** claims — same line, same owner, different rows — share the row rather than contending.
 *   Two typedefs really can sit on one source line (`typedef A x;` and `typedef B y;`), and making
 *   them fight drops one of a legal pair. Exclusivity exists to stop a misattributed type body from
 *   evicting a function body, which is a contest *between* owners; within an owner they are peers.
 */
fun allocate(claims: List<Claim>, maxLine: Int): Allocation {
    // Identical *declarations* at one line are the same declaration seen twice — that is where the
    // `×N` instantiation and inlined-copy counts come from. Identical *statements* are not: two
    // regions with the same text are two executions of it, and collapsing them loses code. So only
    // [Anchoring.EXACT] claims merge.
    val (mergeable, distinct) = claims.partition { it.anchoring == Anchoring.EXACT }
    val merged = mergeable
        .groupBy { Triple(it.owner, it.line, it.rows) }
        .map { (_, same) -> same.first() to same.size } + distinct.map { it to 1 }

    // Misattributed claims sort last, so one can never take a row a well-attested claim wanted.
    // Among elastic peers on one line the fullest reserves — it has the most to show and the others
    // fold losslessly onto the row it took — tie-broken by text so the choice cannot drift with an
    // unrelated change. Rigid claims are left tied, keeping their arrival order.
    //
    // Neither tie-break applies to a *body*, whose claims are consecutive stretches of one decompiled
    // function and must stay in the order the decompiler emitted them. Sorting them by size and text
    // alphabetised the statements inside a function: xvimage.cpp's first constructor got its closing
    // brace two rows before its last two statements, which then parsed at file scope. `sortedWith` is
    // stable, so comparing equal here is what preserves arrival order.
    fun Claim.tie(v: Int) = if (fit == Fit.ELASTIC && owner.group != "body") v else 0
    val order = compareBy<Pair<Claim, Int>>(
        { it.first.stale },
        { it.first.owner.ordinal },
        { it.first.line ?: Int.MAX_VALUE },
        // Rigid before elastic among peers: a function's signature is one row and must open the row
        // its body shares, and a one-row typedef keeps its line under an expanding initializer.
        { if (it.first.fit == Fit.ELASTIC) 1 else 0 },
        { it.first.tie(-it.first.rows.size) },
        { if (it.first.fit == Fit.ELASTIC && it.first.owner.group != "body") it.first.rows.first().text else "" },
    )

    // Who holds each row. A peer — same owner, same attribution — shares it rather than contending;
    // anyone else is turned away. `typedef A x;` and `typedef B y;` really can sit on one source line,
    // and making them fight drops one of a legal pair. Exclusivity is for contests *between* owners.
    val held = mutableMapOf<Int, String>()
    val placed = mutableListOf<Placement>()
    val dropped = mutableListOf<Dropped>()

    // Anchored first — floating claims fill what is left of the band above them, so they need to know
    // where the content starts.
    val (anchored, floating) = merged.sortedWith(order).partition { it.first.anchoring != Anchoring.BAND }

    // (claim, copies, row) — the row it *resolved to*, which for an AFTER claim is not the one it
    // asked for. Re-reading `claim.line` here put every crammed statement back on its own anchor.
    val shared = mutableListOf<Triple<Claim, Int, Int>>()
    var cursor = 1
    val reserved = anchored.mapNotNull { (claim, copies) ->
        val asked = claim.line
        // AFTER slides to the first free row at or past what it asked for, and keeps a cursor so a
        // claim with no line of its own follows whatever came before it.
        val line = when (claim.anchoring) {
            // Its own line when that is still free, even if a later-ordered claim already ran past
            // it — Ghidra emits branches out of source order, and holding a cursor floor sent
            // everything after the first out-of-order block to the bottom of the span. Only a claim
            // with no line of its own follows the cursor.
            // Never fails. Decompiled code exists and has to go somewhere: when every row in the
            // window is taken it crams onto the last usable one, which is how a body that outgrows
            // its span has always been handled. Dropping is right for a declaration — one placed two
            // rows from its line is a lie — and wrong here, where it silently loses statements.
            Anchoring.AFTER -> {
                val from = asked ?: cursor
                val ceiling = claim.limit?.coerceAtMost(maxLine) ?: maxLine
                (from..ceiling).firstOrNull { it !in held } ?: ceiling.takeIf { it >= 1 }
            }

            else -> asked
        } ?: return@mapNotNull dropped.add(Dropped(claim, NO_ROOM)).let { null }
        if (claim.anchoring == Anchoring.AFTER) cursor = line + 1
        when {
            line !in 1..maxLine -> dropped.add(Dropped(claim, OFF_CANVAS)).let { null }
            // A peer of the holder rides the row it already took; only the first expands. Peerage is
            // by owner alone — a misattributed local shares its line with a real one, as it always
            // has; `stale` decides who reserves *first*, which is what stops it taking the row.
            held[line] == claim.owner.group -> shared.add(Triple(claim, copies, line)).let { null }
            line in held -> dropped.add(Dropped(claim, ROW_TAKEN)).let { null }
            else -> {
                held[line] = claim.owner.group
                Triple(claim, copies, line)
            }
        }
    }

    for ((claim, copies, line) in reserved) {
        val ceiling = claim.limit?.coerceAtMost(maxLine) ?: maxLine
        val wanted = if (claim.fit == Fit.RIGID) claim.rows.size else ceiling - line + 1
        val end = (line + 1 until line + wanted).takeWhile { it <= ceiling && it !in held }.lastOrNull() ?: line
        (line..end).forEach { held[it] = claim.owner.group }
        placed += Placement(claim, line..end, copies)
    }
    // Peers take exactly the row they share, never the extent its holder expanded to.
    shared.mapTo(placed) { (claim, copies, row) -> Placement(claim, row..row, copies) }

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
        (row..end).forEach { held[it] = claim.owner.group }
        placed += Placement(claim, row..end, copies)
        next = end + 1
    }

    return Allocation(placed, dropped)
}

/**
 * [rows] laid into [range], one per row while it lasts and the remainder joined onto the last —
 * `Canvas.layoutBraceBlock`'s three cases (spread, partial spread with a crammed tail, everything on
 * one line) as a single fold, now that the range is decided before any of it is written.
 *
 * Returns row index to text, so a caller that also wants the indent can zip against [rows].
 */
fun fitRows(rows: List<Row>, range: IntRange): List<Pair<Int, Row>> {
    val room = range.count()
    if (rows.size <= room) return rows.mapIndexed { i, r -> range.first + i to r }
    // The last slot takes everything that didn't fit, joined; each earlier slot takes one row.
    val head = rows.take(room - 1).mapIndexed { i, r -> range.first + i to r }
    val tail = rows.drop(room - 1)
    return head + (range.last to tail.first().copy(text = tail.joinToString(" ") { it.text.trim() }))
}
