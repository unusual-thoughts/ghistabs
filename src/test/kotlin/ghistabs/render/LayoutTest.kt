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
            this += Fragment(note = "0x1000", kind = FragmentKind.SLINE) // comment-only
            this += Fragment(code = "int x;", note = "(param)", kind = FragmentKind.DECL_LOCAL)
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

    @Test
    fun `wrapDecompLine splits a long condition at its top-level boolean boundaries`() {
        val text = "if ((a == 1) && (b == 2) && (c == 3)) {"
        val rows = wrapDecompLine(text, depth = 2, minLen = 10)
        // Cuts at the two depth-1 ` && ` (between the parenthesized clauses), not inside them; head keeps
        // its indent, continuations step in by 2, operators end their rows, the trailing `{` stays put.
        assertEquals(3, rows.size)
        assertEquals(listOf(2, 4, 4), rows.map { it.first })
        assert(rows[0].second.endsWith("&&") && rows[1].second.endsWith("&&")) { rows.toString() }
        assert(rows.last().second.endsWith("{")) { rows.toString() }
        // No content lost or reordered across the split.
        assertEquals(text.filterNot { it == ' ' }, rows.joinToString("") { it.second }.filterNot { it == ' ' })
    }

    @Test
    fun `wrapDecompLine leaves a short line, or a long one without boolean operators, intact`() {
        assertEquals(listOf(2 to "x = f(a, b);"), wrapDecompLine("x = f(a, b);", depth = 2, minLen = 40))
        // Long, but only commas (inside a call) — never split, so arg lists stay whole.
        val call = "r = call(alpha, beta, gamma, delta, epsilon, zeta, eta, theta, iota, kappa);"
        assertEquals(listOf(2 to call), wrapDecompLine(call, depth = 2, minLen = 20))
    }

    @Test
    fun `trims trailing blank lines but keeps misattributed content that carries code`() {
        val canvas = Canvas(6).apply {
            this[2] += Fragment(0, code = "int real;", note = "(global)", kind = FragmentKind.DECL_GLOBAL)
            this[5] += Fragment(0, code = "int stale;", note = "", kind = FragmentKind.TYPEDEF, stale = true)
        }
        // Line 5 is misattributed but carries code, so it survives; only the blank tail past it goes.
        // Trimming on staleness alone deleted `class XVImage` and its whole body from xvimage.h the
        // moment nothing happened to sit below it.
        assertEquals(
            listOf("", "int real;  // L   2 (global)", "", "", "int stale;  // L   5 stale N_SOL?"),
            canvas.render(trim = true).trimEnd('\n').split('\n'),
        )
    }

    @Test
    fun `repeated line tags on one row collapse, distinct ones do not`() {
        val line = TargetLine(139).apply {
            this += Fragment(code = "typedef unsigned char _Value_type;", note = "", kind = FragmentKind.TYPEDEF)
            this += Fragment(code = "typedef Exclusion _Value_type;", note = "", kind = FragmentKind.TYPEDEF)
            this += Fragment(code = "int p;", note = "(param)", kind = FragmentKind.DECL_LOCAL)
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
