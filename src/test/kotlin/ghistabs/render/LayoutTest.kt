package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of the layout engine: the three ways [Canvas.layoutBraceBlock]
 * fits a block into the blank run below it, and the invariant that a [TargetLine]
 * renders all code before any comment so a `//` never comments out a later fragment's
 * code. Comments are derived from the line index at render time.
 */
class LayoutTest {
    private fun typeBodyOpen(code: String) = Fragment(0, code, note = "", kind = FragmentKind.TYPE_BODY)

    @Test
    fun `spreads one item per line when there is room`() {
        val canvas = Canvas(5).apply {
            layoutBraceBlock(1, typeBodyOpen("struct S {"), listOf("int a;", "int b;"), "};")
        }
        assertEquals(
            listOf("struct S {  // L   1", "    int a;", "    int b;", "};"),
            canvas.toString().trimEnd('\n').split('\n'),
        )
    }

    @Test
    fun `crams overflow and close onto the last blank line when the run is short`() {
        // maxLine 3 → open on line 1 leaves lines 2,3 blank: one item on 2, the rest cram on 3.
        val canvas = Canvas(3).apply {
            layoutBraceBlock(1, typeBodyOpen("enum E {"), listOf("a,", "b,", "c,"), "};")
        }
        assertEquals(
            listOf("enum E {  // L   1", "    a,", "    b, c, };"),
            canvas.toString().trimEnd('\n').split('\n'),
        )
    }

    @Test
    fun `folds onto one line with the tag after the code when there is no room below`() {
        val canvas = Canvas(1).apply {
            layoutBraceBlock(1, typeBodyOpen("struct S {"), listOf("int a;", "int b;"), "};")
        }
        val line = canvas.toString().trimEnd('\n')
        assertEquals("struct S { int a; int b; };  // L   1", line)
        // Comment last: nothing but the tag sits to the right of `//`.
        assertEquals("// L   1", line.substring(line.indexOf("//")))
    }

    @Test
    fun `a brace block expands through and evicts a lone stale line`() {
        // A misattributed (stale) decl sits on line 2, directly below the opener on line 1,
        // with blank room beyond. The block expands through it — evicting the stale fragment —
        // instead of folding everything onto line 1.
        val canvas = Canvas(5).apply {
            this[2] += Fragment(0, code = "int misattributed;", note = "", kind = FragmentKind.DECL_LOCAL, stale = true)
            layoutBraceBlock(1, typeBodyOpen("struct S {"), listOf("int a;", "int b;"), "};")
        }
        assertEquals(
            listOf("struct S {  // L   1", "    int a;", "    int b;", "};"),
            canvas.toString().trimEnd('\n').split('\n'),
        )
    }

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
    fun `spreadBlocks gives full size with gaps when they fit, proportional shares when they don't`() {
        // 3 blocks (2+3+4 = 9 rows) into rows 21..33 (13) → 4 slack spread as gaps; no block stranded.
        assertEquals(listOf(22, 25, 30), spreadBlocks(20, 33, listOf(2, 3, 4)))
        // Exact fit: no slack, blocks butt together from the top.
        assertEquals(listOf(1, 3), spreadBlocks(0, 5, listOf(2, 3)))
        // Overflow: 9 rows into 5 → proportional shares [1,1,2] butted from the top, none starved.
        assertEquals(listOf(1, 2, 4), spreadBlocks(0, 5, listOf(2, 3, 4)))
        assertEquals(emptyList<Int>(), spreadBlocks(0, 10, emptyList()))
    }

    @Test
    fun `wrapDecompLine splits a long condition at its top-level boolean boundaries`() {
        val text = "if ((a == 1) && (b == 2) && (c == 3)) {"
        val rows = wrapDecompLine(text, depth = 2, minLen = 10)
        // Cuts at the two depth-1 ` && ` (between the parenthesised clauses), not inside them; head keeps
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
    fun `trims trailing blank and stale-only lines`() {
        val canvas = Canvas(6).apply {
            this[2] += Fragment(0, code = "int real;", note = "(global)", kind = FragmentKind.DECL_GLOBAL)
            this[5] += Fragment(0, code = "int stale;", note = "", kind = FragmentKind.TYPEDEF, stale = true)
        }
        // Line 5 is stale-only and 3,4,6 blank → trimmed output ends at line 2.
        assertEquals(listOf("", "int real;  // L   2 (global)"), canvas.render(trim = true).trimEnd('\n').split('\n'))
    }
}
