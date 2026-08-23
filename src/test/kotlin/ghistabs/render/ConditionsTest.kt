package ghistabs.render

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of [uninvertConditions]: which way round gcc's line table says the source had an
 * `if`/`else`, and the cases where it must not answer.
 *
 * Rows are built carrying the structure the token tree gave them — the condition's extent and which
 * rows each branch took — rather than text for the pass to scan back out. Reading that structure
 * *off* the tokens is exercised against real decompiler output; what is pinned here is what the pass
 * then does with it.
 */
class ConditionsTest {
    private fun stmt(text: String) = DecompLine(text, null)

    private fun row(text: String) =
        DecompLine(text, null, braces = text.mapIndexedNotNull { i, c -> Brace(c, i).takeIf { c in "{}" } })

    /** A row ending in `if (<condition>) {`, whose branches took [then] and [otherwise]. */
    private fun ifOpen(text: String, condition: String, then: IntRange, otherwise: IntRange) = row(text).copy(
        ifCondition = text.indexOf(condition).let { it..<it + condition.length },
        branches = Branches(then, otherwise),
    )

    /** An `if` with no plain `else` — no `else` at all, or an `else if` chain, which has no brace. */
    private fun ifAlone(text: String, condition: String) =
        row(text).copy(ifCondition = text.indexOf(condition).let { it..<it + condition.length })

    // `depth` stands in for the address a row is anchored by: the pass copies the row it negates, so
    // there is no identity left to key the lookup on, and nothing else here reads the indent.
    private fun uninvert(vararg rows: Pair<DecompLine, Int?>): List<String> =
        rows.mapIndexed { i, (line, _) -> line.copy(depth = i) }
            .uninvertConditions { rows[it.depth].second }
            .map { it.text }

    // `IsConvertableToLong`: the else-branch anchors above the then-branch, so the source wrote it
    // first and its condition was this one's negation.
    @Test
    fun `an else-branch anchored above its then-branch is swapped and the condition negated`() {
        uninvert(
            ifOpen("if (uVar1 < 5) {", "uVar1 < 5", 1..1, 3..3) to 2799,
            stmt("  work();") to 2802,
            row("} else {") to null,
            stmt("  local_c = false;") to 2800,
            row("}") to null,
        ) mustBe listOf("if (!(uVar1 < 5)) {", "  local_c = false;", "} else {", "  work();", "}")
    }

    // Ghidra emits `}` and `else {` as separate rows at equal indent; the branch groups say the same
    // thing either way, so the extra separator row just rides along between them.
    @Test
    fun `the two-row else Ghidra emits keeps its separator between the branches`() {
        uninvert(
            ifOpen("if (uVar1 < 5) {", "uVar1 < 5", 1..1, 4..4) to 2799,
            stmt("  work();") to 2802,
            row("}") to null,
            row("else {") to null,
            stmt("  local_c = false;") to 2800,
            row("}") to null,
        ) mustBe listOf("if (!(uVar1 < 5)) {", "  local_c = false;", "}", "else {", "  work();", "}")
    }

    // Only the `if` that opens the block at the end of the row is negated — the row also carries an
    // earlier statement and an earlier `if`, which is the folded head's shape.
    @Test
    fun `only the condition the row's own branches belong to is negated`() {
        uninvert(
            ifOpen("void f() { if (a != false) { if (b == c) {", "b == c", 1..1, 3..3) to 60,
            stmt("  x();") to 63,
            row("} else {") to null,
            stmt("  y();") to 61,
            row("}") to null,
        ) mustBe listOf("void f() { if (a != false) { if (!(b == c)) {", "  y();", "} else {", "  x();", "}")
    }

    @Test
    fun `a branch pair already in source order is left alone`() {
        uninvert(
            ifOpen("if (uVar1 < 5) {", "uVar1 < 5", 1..1, 3..3) to 2799,
            stmt("  work();") to 2800,
            row("} else {") to null,
            stmt("  local_c = false;") to 2802,
            row("}") to null,
        ) mustBe listOf("if (uVar1 < 5) {", "  work();", "} else {", "  local_c = false;", "}")
    }

    // An `if` with no branch pair — no `else`, or an `else if` chain — is never touched, so a chain's
    // second condition cannot be stranded under a negated first.
    @Test
    fun `an if with no branch pair, or with an unanchored branch, is left alone`() {
        uninvert(
            ifAlone("if (a) {", "a") to 20,
            stmt("  x();") to 21,
            row("} else if (b) {") to null,
            stmt("  y();") to 19,
            row("}") to null,
        ) mustBe listOf("if (a) {", "  x();", "} else if (b) {", "  y();", "}")
        uninvert(
            ifOpen("if (a) {", "a", 1..1, 3..3) to 10,
            stmt("  x();") to null,
            row("} else {") to null,
            stmt("  y();") to 9,
            row("}") to null,
        ) mustBe listOf("if (a) {", "  x();", "} else {", "  y();", "}")
    }

    // Nested swaps: the inner `if` goes first, because the outer one's swap moves whole branch blocks
    // and would carry the inner one's rows out from under its recorded extents.
    @Test
    fun `a nested if-else is swapped inside the outer one that also swaps`() {
        uninvert(
            ifOpen("if (a) {", "a", 1..5, 7..7) to 100,
            ifOpen("  if (b) {", "b", 2..2, 4..4) to 102,
            stmt("    inner-then;") to 103,
            row("  } else {") to null,
            stmt("    inner-else;") to 101,
            row("  }") to null,
            row("} else {") to null,
            stmt("  outer-else;") to 99,
            row("}") to null,
        ) mustBe listOf(
            "if (!(a)) {",
            "  outer-else;",
            "} else {",
            "  if (!(b)) {",
            "    inner-else;",
            "  } else {",
            "    inner-then;",
            "  }",
            "}",
        )
    }
}
