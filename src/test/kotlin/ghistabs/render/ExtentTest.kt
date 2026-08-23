package ghistabs.render

import ghistabs.render.FileRenderer.Companion.believedLength
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustNot
import org.junit.jupiter.api.Test

/** What a file's real length is allowed to decide, and what disqualifies it. */
class ExtentTest {
    @Test
    fun `a length the code fits inside is the extent`() {
        believedLength(291, code = 280) { error("no conflict") } mustBe 291
        believedLength(291, code = 291) { error("the last line is inside the file") } mustBe 291
    }

    /** The wrong version of a header: same path, shifted lines, and code that cannot be there. */
    @Test
    fun `code past the end refuses the length and says so`() {
        val conflicts = mutableListOf<Int>()
        believedLength(291, code = 340) { conflicts += it } mustBe null
        conflicts mustBe listOf(291)
    }

    @Test
    fun `no local file, no length`() {
        believedLength(null, code = 340) { error("nothing to conflict with") } mustBe null
    }

    /** A header nothing was inlined out of: no code is the absence of a refutation, not a doubt. */
    @Test
    fun `no code at all keeps the length`() {
        believedLength(291, code = null) { error("no code cannot conflict") } mustBe 291
    }

    @Test
    fun `a file that reaches nothing is reached past by any line`() {
        1.must { beyond(null) }
        null.mustNot("no line is past nothing") { beyond(null) }
        null.mustNot { beyond(10) }
        11.must { beyond(10) }
        10.mustNot("the extent is the last line the file reaches, not the first it does not") { beyond(10) }
    }

    @Test
    fun `an extent is the furthest line attested, or nothing`() {
        extentOf(null, 12, 40, null) mustBe 40
        extentOf(null, null) mustBe null
        extentOf() mustBe null
    }
}
