package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of the layout engine's two non-obvious behaviours: the three
 * ways [Canvas.layoutBraceBlock] fits a block into the blank run below it, and the
 * invariant that [TargetLine] always renders code before comments so a `//` can
 * never comment out a following fragment's code.
 */
class LayoutTest {
    private fun canvasWith(maxLine: Int, block: Canvas.() -> Unit) = Canvas(maxLine).apply(block)

    @Test
    fun `spreads one item per line when there is room`() {
        val canvas = canvasWith(5) {
            layoutBraceBlock(1, "", "struct S {", "// L1", listOf("int a;", "int b;"), "};", "", " ")
        }
        assertEquals(
            listOf("struct S {  // L1", "    int a;", "    int b;", "};"),
            canvas.toString().trimEnd('\n').split('\n'),
        )
    }

    @Test
    fun `crams overflow and close onto the last blank line when the run is short`() {
        // maxLine 3 → open on line 1 leaves only lines 2,3 blank: one item fits on 2,
        // the rest (b, c) + close cram onto 3.
        val canvas = canvasWith(3) {
            layoutBraceBlock(1, "", "enum E {", "// L1", listOf("a", "b", "c"), "};", ",", ", ")
        }
        assertEquals(
            listOf("enum E {  // L1", "    a,", "    b, c };"),
            canvas.toString().trimEnd('\n').split('\n'),
        )
    }

    @Test
    fun `folds onto one line with the tag after the code when there is no room below`() {
        // Single line available: the whole block folds. The tag must ride the comment
        // slot so it lands after the members — folding it mid-line would comment them out.
        val canvas = canvasWith(1) {
            layoutBraceBlock(1, "", "struct S {", "// L1", listOf("int a;", "int b;"), "};", "", " ")
        }
        val line = canvas.toString().trimEnd('\n')
        assertEquals("struct S { int a; int b; };  // L1", line)
        // The comment is last: nothing of substance sits to the right of `//`.
        assertEquals("// L1", line.substring(line.indexOf("//")))
    }

    @Test
    fun `renders all code before any comment regardless of fragment order`() {
        val line = TargetLine().apply {
            this += Fragment(comment = "// L17 @ 0x1000")
            this += Fragment(code = "int x;", comment = "// L17 (param)")
            this += Fragment(code = "int y;")
        }
        // Both code fragments precede both comments — no `//` swallows `int y;`.
        assertEquals("int x;   int y;  // L17 @ 0x1000 // L17 (param)", line.toString())
    }

    @Test
    fun `indent comes from the first fragment and empty lines render blank`() {
        assertEquals("", TargetLine().toString())
        val line = TargetLine().apply { this += Fragment("    ", code = "return 0;") }
        assertEquals("    return 0;", line.toString())
    }
}
