package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of what is left in Layout once allocation moved to [allocate]: how a
 * [TargetLine] renders the fragments sharing a row, and how an over-long condition wraps.
 * Placement itself is covered by ClaimsTest.
 */
class LayoutTest {
    @Test
    fun `renders all code before any comment regardless of fragment order`() {
        val line = TargetLine(17).apply {
            this += Fragment(note = "0x1000", shape = NoteShape.SLINE) // comment-only
            this += Fragment(code = "int x;", note = "(param)")
            this += Fragment(code = "int y;") // pure code
        }
        // Both code fragments precede both comments — no `//` swallows `int y;`.
        assertEquals("int x;   int y;  // L  17 @ 0x1000 // L  17 (param)", line.render())
    }

    @Test
    fun `indent is a space count from the first fragment and empty lines render blank`() {
        assertEquals("", TargetLine(1).render())
        val line = TargetLine(1).apply { this += Fragment(4, code = "return 0;") }
        assertEquals("    return 0;", line.render())
    }

    // The cuts a row's tokens would have given: just past each ` && `/` || `, at its paren depth.
    private fun cutsOf(text: String) = buildList {
        var depth = 0
        text.forEachIndexed { i, c ->
            when (c) {
                '(', '[' -> depth++
                ')', ']' -> depth--
                ' ' -> if (text.regionMatches(i + 1, "&& ", 0, 3) || text.regionMatches(i + 1, "|| ", 0, 3)) {
                    add(Cut(i + 4, depth))
                }
            }
        }
    }

    @Test
    fun `wrapDecompLine splits a long condition at its shallowest boolean boundaries`() {
        val text = "if ((a == 1) && (b == 2) && (c == 3)) {"
        val rows = wrapDecompLine(text, depth = 2, cuts = cutsOf(text), minLen = 10)
        // Cuts at the two depth-1 ` && ` (between the parenthesized clauses), not inside them; head keeps
        // its indent, continuations step in by 2, operators end their rows, the trailing `{` stays put.
        assertEquals(3, rows.size)
        assertEquals(listOf(2, 4, 4), rows.map { it.first })
        assert(rows[0].second.endsWith("&&") && rows[1].second.endsWith("&&")) { rows.toString() }
        assert(rows.last().second.endsWith("{")) { rows.toString() }
        // No content lost or reordered across the split.
        assertEquals(text.filterNot { it == ' ' }, rows.joinToString("") { it.second }.filterNot { it == ' ' })
    }

    // A nested boundary splits the piece it lands in, once that piece is still too long on its own.
    @Test
    fun `a deeper boundary splits the piece it falls in, not the whole row`() {
        val text = "if ((a == 1 && b == 2) || (c == 3 && d == 4)) {"
        val rows = wrapDecompLine(text, depth = 0, cuts = cutsOf(text), minLen = 20)
        assertEquals(4, rows.size)
        assertEquals(listOf(0, 2, 2, 2), rows.map { it.first })
        assertEquals(text.filterNot { it == ' ' }, rows.joinToString("") { it.second }.filterNot { it == ' ' })
    }

    @Test
    fun `wrapDecompLine leaves a short line, or a long one with no boundary, intact`() {
        val short = "x = f(a, b);"
        assertEquals(listOf(2 to short), wrapDecompLine(short, depth = 2, cuts = cutsOf(short), minLen = 40))
        // Long, but only commas (inside a call) — never split, so arg lists stay whole.
        val call = "r = call(alpha, beta, gamma, delta, epsilon, zeta, eta, theta, iota, kappa);"
        assertEquals(listOf(2 to call), wrapDecompLine(call, depth = 2, cuts = cutsOf(call), minLen = 20))
    }

    @Test
    fun `trims the blank tail past the last line that carries anything`() {
        val canvas = Canvas(6).apply {
            this[2] += Fragment(0, code = "int real;", note = "(global)")
            this[5] += Fragment(0, code = "int last;", note = "")
        }
        // Only the blank tail past line 5 goes. Trimming on a staleness flag once deleted
        // `class XVImage` and its whole body from xvimage.h the moment nothing sat below it.
        assertEquals(
            listOf("", "int real;  // L   2 (global)", "", "", "int last;  // L   5"),
            canvas.render(trim = true).trimEnd('\n').split('\n'),
        )
    }

    @Test
    fun `an inline marker moves inside the block it emptied, however the row was assembled`() {
        // The `{` and its `}` reach the row as two fragments, so dropInlined never saw them as a pair.
        val split = TargetLine(584).apply {
            this += Fragment(code = "for (p = start; p != end; p = p + 1) {")
            this += Fragment(code = "} /* ⇐ inlines stl_vector.h L 123 */ /* ⇐ inlines stl_algobase.h L 371 */")
        }
        assertEquals(
            "for (p = start; p != end; p = p + 1) { /* ⇐ inlines stl_vector.h L 123 */ " +
                "/* ⇐ inlines stl_algobase.h L 371 */ }",
            split.render(),
        )
        // The .cpp side, where the marker is the call standing in for the inlined body.
        val called = TargetLine(42).apply {
            this += Fragment(code = "while (i < n) { }   uVar1 = __inline_stl_vector_h_123(this, i);")
        }
        assertEquals("while (i < n) { uVar1 = __inline_stl_vector_h_123(this, i); }", called.render())
        // Ghidra's own empty block, with no marker after it, stays as it is.
        val bare = TargetLine(9).apply { this += Fragment(code = "while (f(x)) { }   g(y);") }
        assertEquals("while (f(x)) { }   g(y);", bare.render())
    }

    @Test
    fun `repeated line tags on one row collapse, distinct ones do not`() {
        val line = TargetLine(139).apply {
            this += Fragment(code = "typedef unsigned char _Value_type;", note = "")
            this += Fragment(code = "typedef Exclusion _Value_type;", note = "")
            this += Fragment(code = "int p;", note = "(param)")
        }
        // Every fragment restates the row's own line, so the two bare tags are one fact stated twice;
        // the `(param)` one says something else and survives.
        assertEquals(
            "typedef unsigned char _Value_type;   typedef Exclusion _Value_type;   int p;  " +
                "// L 139 // L 139 (param)",
            line.render(),
        )
    }
}
