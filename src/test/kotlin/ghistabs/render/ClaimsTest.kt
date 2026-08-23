package ghistabs.render

import ghistabs.test.mustBe
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
        val out = allocate(listOf(a, b), range = 1..40)
        out.at(10).range mustBe 10..10
        out.at(12).range mustBe 12..12
        out.dropped mustBe emptyList<Dropped>()
    }

    @Test
    fun `an elastic claim runs to the next held row, not to the end of the file`() {
        // A big array knows where it starts, not where it ends; the typedef at 15 stops it.
        val out = allocate(
            listOf(claim(Owner.GLOBAL, 10, fit = Fit.ELASTIC), claim(Owner.TYPEDEF, 15)),
            range = 1..40,
        )
        out.at(10).range mustBe 10..14
        out.at(15).range mustBe 15..15
    }

    @Test
    fun `an expanding claim stops at a reservation it outranks`() {
        // FUNCTION_BODY outranks TYPEDEF, but the typedef reserved 13 in phase one, so the elastic
        // body stops at 12. Priority decides contested rows, not how far a winner may spread.
        val out = allocate(
            listOf(claim(Owner.FUNCTION_BODY, 10, fit = Fit.ELASTIC), claim(Owner.TYPEDEF, 13)),
            range = 1..40,
        )
        out.at(13).range mustBe 13..13
        out.at(10).range mustBe 10..12
    }

    @Test
    fun `priority breaks a genuine tie and the loser is dropped with a reason, never displaced`() {
        // Both want row 10 outright. §29's sweep demoted the loser to a `// stray:` blob; it is now a
        // dropped claim carrying why, which the renderer may trace and the diagnostics always count.
        val body = claim(Owner.FUNCTION_BODY, 10)
        val typedef = claim(Owner.TYPEDEF, 10)
        val out = allocate(listOf(typedef, body), range = 1..40)
        out.at(10).range mustBe 10..10
        out.at(10).claim.owner mustBe Owner.FUNCTION_BODY
        out.dropped.map { it.claim } mustBe listOf(typedef)
    }

    @Test
    fun `identical claims merge with a count instead of stacking`() {
        // A header line is compiled into every call site, so N identical claims arrive for one line.
        val copies = List(4) { claim(Owner.FUNCTION_BODY, 38) }
        val out = allocate(copies, range = 1..40)
        out.placed.size mustBe 1
        out.at(38).copies mustBe 4
        out.dropped mustBe emptyList<Dropped>()
    }

    @Test
    fun `peers of one owner on one line share the row instead of contending`() {
        // `typedef A x;` and `typedef B y;` on one source line is legal and both must render.
        // Exclusivity is for contests *between* owners, not within one.
        val a = Claim(Owner.TYPEDEF, 7, listOf(Row("typedef int A;")))
        val b = Claim(Owner.TYPEDEF, 7, listOf(Row("typedef long B;")))
        val out = allocate(listOf(a, b), range = 1..40)
        out.dropped mustBe emptyList<Dropped>()
        // Both placed, both on row 7, each keeping its own rows — the renderer joins them.
        val onSeven = out.placed.filter { it.range == 7..7 }
        onSeven.flatMap { it.claim.rows }.map { it.text } mustBe listOf("typedef int A;", "typedef long B;")
    }

    @Test
    fun `floating claims fill the band above the first anchored row`() {
        val a = Claim(Owner.INCLUDE, null, listOf(Row("#include \"a.h\"")))
        val b = Claim(Owner.INCLUDE, null, listOf(Row("#include \"b.h\"")))
        val out = allocate(listOf(a, b, claim(Owner.FUNCTION_BODY, 5)), range = 1..40)
        out.placed.filter { it.claim.owner == Owner.INCLUDE }.map { it.range } mustBe listOf(1..1, 2..2)
        out.at(5).range mustBe 5..5
    }

    @Test
    fun `a floating claim with no band left is dropped, not crammed onto content`() {
        val out = allocate(listOf(claim(Owner.INCLUDE, null), claim(Owner.FUNCTION_BODY, 1)), range = 1..40)
        out.dropped.map { it.claim.owner } mustBe listOf(Owner.INCLUDE)
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
        val out = allocate(claims, range = 1..10)
        out.placed.sumOf { it.copies } + out.dropped.size mustBe claims.size
        // GLOBAL's line 99 is past the canvas, and TYPE_BODY wanted row 3, which the higher-priority
        // FUNCTION_BODY reserved. Neither is clamped onto a neighbour; both are dropped with a reason.
        out.dropped.map { it.claim.owner }.sorted() mustBe listOf(Owner.GLOBAL, Owner.TYPE_BODY)
    }

    @Test
    fun `fitRows spreads while there is room and crams the remainder onto the last slot`() {
        val rows = listOf(Row("struct S {"), Row("int a;"), Row("int b;"), Row("};"))
        // Room for all four.
        fitRows(rows, 10..13).map { it.first } mustBe listOf(10, 11, 12, 13)
        // Three slots: two spread, the rest joined onto the last — layoutBraceBlock's middle case.
        val tight = fitRows(rows, 10..12)
        tight.map { it.first } mustBe listOf(10, 11, 12)
        tight.last().second.text mustBe "int b; };"
        // One slot: everything on it.
        fitRows(rows, 10..10).single().second.text mustBe "struct S { int a; int b; };"
    }

    @Test
    fun `a misattributed claim never takes a row a body wanted`() {
        val body = claim(Owner.FUNCTION_BODY, 10)
        val bogus = Claim(Owner.GLOBAL, 10, listOf(Row("int splayed;")), stale = true)
        val out = allocate(listOf(bogus, body), range = 1..40)
        out.at(10).claim.owner mustBe Owner.FUNCTION_BODY
        out.dropped.map { it.claim } mustBe listOf(bogus)
        // Between declarations there is no contest: a misattributed one shares the row, as it always
        // has. Exclusivity is body-versus-declaration, which is the contest that used to end in
        // demoting the loser to a `// stray:` comment.
        val real = claim(Owner.TYPEDEF, 20)
        val alsoBogus = Claim(Owner.GLOBAL, 20, listOf(Row("int splayed;")), stale = true)
        val shared = allocate(listOf(alsoBogus, real), range = 1..40)
        shared.dropped mustBe emptyList<Dropped>()
    }

    @Test
    fun `AFTER slides to the next free row instead of sharing or dropping`() {
        // Ghidra revisits a source line; the second visit is real code that has to go somewhere.
        val a = Claim(Owner.FUNCTION_BODY, 10, listOf(Row("first")), anchoring = Anchoring.AFTER)
        val b = Claim(Owner.FUNCTION_BODY, 10, listOf(Row("second")), anchoring = Anchoring.AFTER)
        val out = allocate(listOf(a, b), range = 1..40)
        out.placed.map { it.range }.sortedBy { it.first } mustBe listOf(10..10, 11..11)
        out.dropped mustBe emptyList<Dropped>()
    }

    @Test
    fun `an AFTER claim with no line follows whatever came before it`() {
        // An inlined-region marker rides its call site rather than floating to the header band.
        val stmt = Claim(Owner.FUNCTION_BODY, 20, listOf(Row("code")), anchoring = Anchoring.AFTER)
        val marker = Claim(Owner.FUNCTION_BODY, null, listOf(Row("/* inlines x.h */")), anchoring = Anchoring.AFTER)
        val out = allocate(listOf(stmt, marker), range = 1..40)
        out.placed.first { it.claim === stmt }.range mustBe 20..20
        out.placed.first { it.claim === marker }.range mustBe 21..21
    }

    @Test
    fun `EXACT is unchanged by the policy — a taken row is still shared or lost`() {
        val body = claim(Owner.FUNCTION_BODY, 10)
        val typedef = claim(Owner.TYPEDEF, 10)
        val out = allocate(listOf(typedef, body), range = 1..40)
        out.at(10).claim.owner mustBe Owner.FUNCTION_BODY
        out.dropped.map { it.claim } mustBe listOf(typedef)
    }

    @Test
    fun `AFTER crams onto its limit rather than dropping when the window is full`() {
        // Decompiled statements exist and have to go somewhere; dropping them loses code silently.
        val claims = (1..5).map {
            Claim(Owner.FUNCTION_BODY, 10, listOf(Row("stmt$it")), anchoring = Anchoring.AFTER, limit = 12)
        }
        val out = allocate(claims, range = 1..40)
        out.dropped mustBe emptyList<Dropped>()
        // Three rows for five claims: 10, 11, 12, then the rest pile onto 12.
        out.placed.map { it.range.first }.sorted() mustBe listOf(10, 11, 12, 12, 12)
    }
}
