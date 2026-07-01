package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pins [commentFor]: each kind's comment shape, and the non-obvious stale-marker
 * separator — "; " after a role, a bare " " after the line ref alone.
 */
class FormatTest {
    @Test
    fun `sline, delim and stray have their own shapes`() {
        assertEquals("// L  17 @ 0x1000: mov", commentFor(17, FragmentKind.SLINE, "0x1000: mov", false))
        assertEquals("/* L  17 — opens Foo */", commentFor(17, FragmentKind.FUNC_DELIM, "opens Foo", false))
        assertEquals("// stray: typedef X;", commentFor(17, FragmentKind.STRAY, "typedef X;", false))
    }

    @Test
    fun `a decl tag carries the role and pads the line ref`() {
        assertEquals("// L   1", commentFor(1, FragmentKind.TYPEDEF, "", false))
        assertEquals("// L  17 (param)", commentFor(17, FragmentKind.DECL_LOCAL, "(param)", false))
    }

    @Test
    fun `the stale marker separates with a semicolon after a role, a space without`() {
        assertEquals("// L  17 stale N_SOL?", commentFor(17, FragmentKind.TYPEDEF, "", true))
        assertEquals("// L  17 (param); stale N_SOL?", commentFor(17, FragmentKind.DECL_LOCAL, "(param)", true))
    }
}
