package ghidrakt
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class IntRangeTest {
    @Test
    fun `ranges sharing a byte overlap, whichever starts first`() {
        (0..<4).overlaps(2..<6) mustBe true
        (2..<6).overlaps(0..<4) mustBe true
        (0..<8).overlaps(2..<4) mustBe true
        (0..<4).overlaps(4..<8) mustBe false
    }

    /** A zero-length component, or a zero-length probe, has no byte to share, even where it starts. */
    @Test
    fun `an empty range overlaps nothing`() {
        (0..<4).overlaps(0.withLength(0)) mustBe false
        (0..<4).overlaps(2.withLength(0)) mustBe false
        2.withLength(0).overlaps(0..<4) mustBe false
        0.withLength(0).overlaps(0.withLength(0)) mustBe false
    }
}
