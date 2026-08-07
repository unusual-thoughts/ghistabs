package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of [uninvertConditions]: which way round gcc's line table says the source had an
 * `if`/`else`, and the cases where it must not answer.
 */
class ConditionsTest {
    // Source lines stand in for the anchors; a structural row (a brace) carries none.
    private fun lines(vararg rows: Pair<String, Int?>) = rows.map { (text, _) -> DecompLine(text, null) }

    private fun uninvert(vararg rows: Pair<String, Int?>): List<String> {
        val at = rows.map { it.second }
        val body = lines(*rows)
        return body.uninvertConditions { line -> at[body.indexOfFirst { it === line }] }.map { it.text }
    }

    // A row carrying an earlier statement and an earlier `if` — the folded head's shape. Only the
    // `if` that opens the block at the end of the row is the one being negated; a greedy match
    // spanned both and produced `if (!(a != false) { if (b`, one paren short.
    @Test
    fun `only the if that opens the row's last block is negated`() {
        assertEquals(
            listOf(
                "void f() { if (a != false) { if (!(b == c)) {",
                "  y();",
                "}",
                "else {",
                "  x();",
                "}",
            ),
            uninvert(
                "void f() { if (a != false) { if (b == c) {" to 60,
                "  x();" to 63,
                "}" to null,
                "else {" to null,
                "  y();" to 61,
                "}" to null,
            ),
        )
    }

    // A condition carrying its own parens: the scan steps over them rather than stopping at the
    // first `(` it meets.
    @Test
    fun `a nested paren in the condition does not end the scan`() {
        assertEquals(
            listOf("if (!(f(a) == g(b))) {", "  y();", "}", "else {", "  x();", "}"),
            uninvert(
                "if (f(a) == g(b)) {" to 10,
                "  x();" to 13,
                "}" to null,
                "else {" to null,
                "  y();" to 11,
                "}" to null,
            ),
        )
    }

    // The shape Ghidra actually emits: `}` and `else {` are separate lines at equal indent, so
    // `compressedDecompLines` never joins them. `IsConvertableToLong` in this spelling.
    @Test
    fun `the two-line else Ghidra emits is recognised and swapped`() {
        assertEquals(
            listOf("if (!(uVar1 < 5)) {", "  local_c = false;", "}", "else {", "  work();", "}"),
            uninvert(
                "if (uVar1 < 5) {" to 2799,
                "  work();" to 2802,
                "}" to null,
                "else {" to null,
                "  local_c = false;" to 2800,
                "}" to null,
            ),
        )
    }

    // `} else if (…)` in the two-line spelling is `}` then `else if (…) {` — still a chain, still
    // left alone.
    @Test
    fun `a two-line else-if chain is left alone`() {
        assertEquals(
            listOf("if (a) {", "  x();", "}", "else if (b) {", "  y();", "}"),
            uninvert(
                "if (a) {" to 20,
                "  x();" to 21,
                "}" to null,
                "else if (b) {" to null,
                "  y();" to 19,
                "}" to null,
            ),
        )
    }

    // `IsConvertableToLong`: the else-branch anchors above the then-branch, so the source wrote it
    // first and its condition was this one's negation.
    @Test
    fun `an else-branch anchored above its then-branch is swapped and the condition negated`() {
        assertEquals(
            listOf("if (!(uVar1 < 5)) {", "  local_c = false;", "} else {", "  work();", "}"),
            uninvert(
                "if (uVar1 < 5) {" to 2799,
                "  work();" to 2802,
                "} else {" to null,
                "  local_c = false;" to 2800,
                "}" to null,
            ),
        )
    }

    @Test
    fun `a branch pair already in source order is left alone`() {
        assertEquals(
            listOf("if (uVar1 < 5) {", "  work();", "} else {", "  local_c = false;", "}"),
            uninvert(
                "if (uVar1 < 5) {" to 2799,
                "  work();" to 2800,
                "} else {" to null,
                "  local_c = false;" to 2802,
                "}" to null,
            ),
        )
    }

    // The `} else {` belongs to the inner `if`, not the outer one — depth, not the first match.
    @Test
    fun `a nested if-else is not mistaken for the outer one's separator`() {
        assertEquals(
            listOf("if (a) {", "  if (b) {", "    x();", "  } else {", "    y();", "  }", "}"),
            uninvert(
                "if (a) {" to 10,
                "  if (b) {" to 11,
                "    x();" to 12,
                "  } else {" to null,
                "    y();" to 13,
                "  }" to null,
                "}" to null,
            ),
        )
    }

    // No else, and a branch with no anchored line at all: nothing to compare, nothing to say.
    @Test
    fun `an if without an else or without anchors is left alone`() {
        assertEquals(listOf("if (a) {", "  x();", "}"), uninvert("if (a) {" to 10, "  x();" to 11, "}" to null))
        assertEquals(
            listOf("if (a) {", "  x();", "} else {", "  y();", "}"),
            uninvert("if (a) {" to 10, "  x();" to null, "} else {" to null, "  y();" to 9, "}" to null),
        )
    }

    // `} else if (…) {` is not the separator this pass accepts, so a chain keeps its second condition
    // with its own branch rather than being stranded under a negated first.
    @Test
    fun `an else-if chain is left alone`() {
        assertEquals(
            listOf("if (a) {", "  x();", "} else if (b) {", "  y();", "}"),
            uninvert(
                "if (a) {" to 20,
                "  x();" to 21,
                "} else if (b) {" to null,
                "  y();" to 19,
                "}" to null,
            ),
        )
    }
}
