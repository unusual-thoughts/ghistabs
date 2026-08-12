package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
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
}
