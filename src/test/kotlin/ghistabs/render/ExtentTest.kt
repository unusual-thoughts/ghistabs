package ghistabs.render

import ghistabs.render.FileRenderer.Companion.believedLength
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** What a file's real length is allowed to decide, and what disqualifies it. */
class ExtentTest {
    @Test
    fun `a length the code fits inside is the extent`() {
        assertEquals(291, believedLength(291, code = 280) { error("no conflict") })
        assertEquals(291, believedLength(291, code = 291) { error("the last line is inside the file") })
    }

    /** The wrong version of a header: same path, shifted lines, and code that cannot be there. */
    @Test
    fun `code past the end refuses the length and says so`() {
        val conflicts = mutableListOf<Int>()
        assertNull(believedLength(291, code = 340) { conflicts += it })
        assertEquals(listOf(291), conflicts)
    }

    @Test
    fun `no local file, no length`() {
        assertNull(believedLength(null, code = 340) { error("nothing to conflict with") })
    }

    /** A header nothing was inlined out of: no code is the absence of a refutation, not a doubt. */
    @Test
    fun `no code at all keeps the length`() {
        assertEquals(291, believedLength(291, code = null) { error("no code cannot conflict") })
    }

    @Test
    fun `a file that reaches nothing is reached past by any line`() {
        assertTrue(1.beyond(null))
        assertFalse(null.beyond(null), "no line is past nothing")
        assertFalse(null.beyond(10))
        assertTrue(11.beyond(10))
        assertFalse(10.beyond(10), "the extent is the last line the file reaches, not the first it does not")
    }

    @Test
    fun `an extent is the furthest line attested, or nothing`() {
        assertEquals(40, extentOf(null, 12, 40, null))
        assertNull(extentOf(null, null))
        assertNull(extentOf())
    }
}
