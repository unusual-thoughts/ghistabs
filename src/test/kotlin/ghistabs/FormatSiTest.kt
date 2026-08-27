package ghistabs

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * [formatSi] exists to fill a fixed-width column, so every case is really the same assertion twice:
 * the text is right, and it fits. A value that overflows the width silently widens the row it was
 * measured into, which is the bug the width argument exists to prevent.
 */
class FormatSiTest {
    private fun Long.si(width: Int = 5) = formatSi(width).fits(width)
    private fun Double.si(width: Int = 5) = formatSi(width).fits(width)
    private fun String.fits(width: Int) = also { length mustBe minOf(length, width) }

    @Test
    fun `digits that fit are left alone`() {
        12L.si() mustBe "12"
        12345L.si() mustBe "12345"
        (-1758L).si() mustBe "-1758"
    }

    @Test
    fun `digits that don't fit take a prefix`() {
        148_000L.si() mustBe "148K"
        1_234_567L.si() mustBe "1.23M"
        4_294_967_295L.si() mustBe "4.29G"
    }

    /** The remainder is a fraction of the divisor, so it needs its leading zeros before truncation. */
    @Test
    fun `a small remainder keeps its leading zeros`() {
        1_050_000L.si() mustBe "1.05M"
        1_005_000L.si() mustBe "1.00M"
    }

    /** `(1_000_000 % 1_000_000).toString()` is `"0"`: one digit where two were being read. */
    @Test
    fun `an exact multiple of the divisor has no remainder to read`() {
        1_000_000L.si() mustBe "1.00M"
        2_000_000_000L.si() mustBe "2.00G"
    }

    @Test
    fun `negatives spend a column on the sign`() {
        (-12345L).si(4) mustBe "-12K"
        (-1_234_567L).si() mustBe "-1.2M"
        (-148_000L).si() mustBe "-148K"
    }

    /** `Long.MIN_VALUE.absoluteValue` is itself — negative — so every magnitude test on it inverts. */
    @Test
    fun `the value with no positive counterpart still fits`() {
        Long.MIN_VALUE.si() mustBe "-9.2E"
        Long.MAX_VALUE.si() mustBe "9.22E"
    }

    @Test
    fun `no width means no abbreviation`() {
        1_234_567L.formatSi() mustBe "1234567"
        Long.MIN_VALUE.formatSi() mustBe "-9223372036854775808"
        1234.5.formatSi() mustBe "1234.5"
    }

    /**
     * Five columns is the floor the function can always honour: a scaled mantissa is up to three
     * digits, the prefix is always one, and a sign is one more. Nothing is left to give up below
     * that — the decimals are already gone, and re-scaling `148K` to `0.1M` spends a column rather
     * than saving one.
     */
    @Test
    fun `five columns fits every shape a value can take`() {
        148_000L.si() mustBe "148K"
        (-148_000L).si() mustBe "-148K"
        (-999.5).si() mustBe "-999"
        Long.MIN_VALUE.si() mustBe "-9.2E"
    }

    /** Four columns holds a three-digit mantissa only while it has no sign to carry. */
    @Test
    fun `four columns fits until the value turns negative`() {
        148_000L.si(4) mustBe "148K"
        1_234_567L.si(4) mustBe "1.2M"
        (-1_234_567L).si(4) mustBe "-1M"
        (-148_000L).formatSi(4) mustBe "-148K" // over budget: 148 and K are all that's left to say
    }

    /** Asking for less than four is asking for a mantissa and a prefix in three columns. */
    @Test
    fun `below four the budget is smaller than the shortest answer`() {
        12345L.si(3) mustBe "12K"
        1_234_567L.si(3) mustBe "1M"
        148_000L.formatSi(3) mustBe "148K"
        1_234_567L.formatSi(1) mustBe "1M"
        999L.formatSi(1) mustBe "999" // no prefix to drop, so the digits stand as they are
    }

    /**
     * A `Long` stops at exa — 1e21 needs ~70 bits and it has 63 — but those magnitudes are ordinary
     * for a double, and a table ending at `E` would spell 1e21 as `1000E` and 1e24 as `1000000E`.
     */
    @Test
    fun `magnitudes past a long's reach still get a prefix`() {
        1e21.si() mustBe "1.00Z"
        1e24.si() mustBe "1.00Y"
        (-1.5e21).si() mustBe "-1.5Z"
        Long.MAX_VALUE.si() mustBe "9.22E" // the largest prefix a long can reach
    }

    /** A double has no exact spelling to fall back on, so it fills the width with decimals instead. */
    @Test
    fun `a double spends its spare columns on decimals`() {
        12.5.si() mustBe "12.50"
        0.125.si() mustBe "0.125"
        1234.5.si() mustBe "1.23K"
        (-12.5).si() mustBe "-12.5"
    }
}
