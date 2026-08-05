package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of the space allocator. Every case here is one the old emit-then-reconcile model
 * got wrong in `render-backlog.md` §29 — see `docs/design-plans/layout-rewrite.md`.
 */
class ClaimsTest {
    private fun claim(owner: Owner, line: Int?, rows: Int = 1, fit: Fit = Fit.RIGID) =
        Claim(owner, line, List(rows) { Row("r$it") }, fit)

    private fun Allocation.at(line: Int) = placed.single { it.range.first == line }

    @Test
    fun `a rigid claim takes its own line and nothing more`() {
        val a = claim(Owner.TYPEDEF, 10)
        val b = claim(Owner.TYPEDEF, 12)
        val out = allocate(listOf(a, b), maxLine = 40)
        assertEquals(10..10, out.at(10).range)
        assertEquals(12..12, out.at(12).range)
        assertEquals(emptyList<Dropped>(), out.dropped)
    }

    @Test
    fun `an elastic claim runs to the next held row, not to the end of the file`() {
        // A big array knows where it starts, not where it ends; the typedef at 15 stops it.
        val out = allocate(
            listOf(claim(Owner.GLOBAL, 10, fit = Fit.ELASTIC), claim(Owner.TYPEDEF, 15)),
            maxLine = 40,
        )
        assertEquals(10..14, out.at(10).range)
        assertEquals(15..15, out.at(15).range)
    }

    @Test
    fun `an expanding claim stops at a reservation it outranks`() {
        // FUNCTION_BODY outranks TYPEDEF, but the typedef reserved 13 in phase one, so the elastic
        // body stops at 12. Priority decides contested rows, not how far a winner may spread.
        val out = allocate(
            listOf(claim(Owner.FUNCTION_BODY, 10, fit = Fit.ELASTIC), claim(Owner.TYPEDEF, 13)),
            maxLine = 40,
        )
        assertEquals(13..13, out.at(13).range)
        assertEquals(10..12, out.at(10).range)
    }

    @Test
    fun `priority breaks a genuine tie and the loser is dropped with a reason, never displaced`() {
        // Both want row 10 outright. §29's sweep demoted the loser to a `// stray:` blob; it is now a
        // dropped claim carrying why, which the renderer may trace and the diagnostics always count.
        val body = claim(Owner.FUNCTION_BODY, 10)
        val typedef = claim(Owner.TYPEDEF, 10)
        val out = allocate(listOf(typedef, body), maxLine = 40)
        assertEquals(10..10, out.at(10).range)
        assertEquals(Owner.FUNCTION_BODY, out.at(10).claim.owner)
        assertEquals(listOf(typedef), out.dropped.map { it.claim })
    }

    @Test
    fun `identical claims merge with a count instead of stacking`() {
        // A header line is compiled into every call site, so N identical claims arrive for one line.
        val copies = List(4) { claim(Owner.FUNCTION_BODY, 38) }
        val out = allocate(copies, maxLine = 40)
        assertEquals(1, out.placed.size)
        assertEquals(4, out.at(38).copies)
        assertEquals(emptyList<Dropped>(), out.dropped)
    }

    @Test
    fun `claims differing only in content contend rather than merging`() {
        // dedup(line, name) used to keep the first and silently drop the rest even when they differed.
        val a = Claim(Owner.TYPEDEF, 7, listOf(Row("typedef int A;")))
        val b = Claim(Owner.TYPEDEF, 7, listOf(Row("typedef long A;")))
        val out = allocate(listOf(a, b), maxLine = 40)
        assertEquals(1, out.placed.size)
        assertEquals(1, out.dropped.size)
        assertEquals(1, out.at(7).copies)
    }

    @Test
    fun `floating claims fill the band above the first anchored row`() {
        val a = Claim(Owner.INCLUDE, null, listOf(Row("#include \"a.h\"")))
        val b = Claim(Owner.INCLUDE, null, listOf(Row("#include \"b.h\"")))
        val out = allocate(listOf(a, b, claim(Owner.FUNCTION_BODY, 5)), maxLine = 40)
        assertEquals(listOf(1..1, 2..2), out.placed.filter { it.claim.owner == Owner.INCLUDE }.map { it.range })
        assertEquals(5..5, out.at(5).range)
    }

    @Test
    fun `a floating claim with no band left is dropped, not crammed onto content`() {
        val out = allocate(listOf(claim(Owner.INCLUDE, null), claim(Owner.FUNCTION_BODY, 1)), maxLine = 40)
        assertEquals(listOf(Owner.INCLUDE), out.dropped.map { it.claim.owner })
    }

    @Test
    fun `every claim is accounted for as placed or dropped`() {
        // The ship gate: no third bucket, so there is nowhere for a `// stray:` dumping ground to live.
        val claims = listOf(
            claim(Owner.FUNCTION_BODY, 3, rows = 2, fit = Fit.ELASTIC),
            claim(Owner.TYPE_BODY, 3),
            claim(Owner.TYPEDEF, 4),
            claim(Owner.GLOBAL, 99),
            claim(Owner.INCLUDE, null),
        )
        val out = allocate(claims, maxLine = 10)
        assertEquals(claims.size, out.placed.sumOf { it.copies } + out.dropped.size)
        // GLOBAL's line 99 is past the canvas, and TYPE_BODY wanted row 3, which the higher-priority
        // FUNCTION_BODY reserved. Neither is clamped onto a neighbour; both are dropped with a reason.
        assertEquals(listOf(Owner.GLOBAL, Owner.TYPE_BODY), out.dropped.map { it.claim.owner }.sorted())
    }

    @Test
    fun `fitRows spreads while there is room and crams the remainder onto the last slot`() {
        val rows = listOf(Row("struct S {"), Row("int a;"), Row("int b;"), Row("};"))
        // Room for all four.
        assertEquals(listOf(10, 11, 12, 13), fitRows(rows, 10..13).map { it.first })
        // Three slots: two spread, the rest joined onto the last — layoutBraceBlock's middle case.
        val tight = fitRows(rows, 10..12)
        assertEquals(listOf(10, 11, 12), tight.map { it.first })
        assertEquals("int b; };", tight.last().second.text)
        // One slot: everything on it.
        assertEquals("struct S { int a; int b; };", fitRows(rows, 10..10).single().second.text)
    }

    @Test
    fun `a misattributed claim never takes a row a well-attested one wanted`() {
        val real = claim(Owner.TYPEDEF, 10)
        val bogus = Claim(Owner.GLOBAL, 10, listOf(Row("int splayed;")), stale = true)
        val out = allocate(listOf(bogus, real), maxLine = 40)
        // GLOBAL outranks TYPEDEF, but stale sorts behind both.
        assertEquals(Owner.TYPEDEF, out.at(10).claim.owner)
        assertEquals(listOf(bogus), out.dropped.map { it.claim })
    }
}
