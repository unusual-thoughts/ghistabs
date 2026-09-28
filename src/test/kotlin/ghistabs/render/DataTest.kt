package ghistabs.render

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Pins [cStyleNumber]: Ghidra's `<hex>h` / zero-run listing format → C literals; other reprs pass through. */
class DataTest {
    @Test
    fun `hex-h becomes 0x, zero runs become 0, other reprs untouched`() {
        cStyleNumber("DEADCAFEh") mustBe "0xDEADCAFE"
        cStyleNumber("5h") mustBe "0x5"
        cStyleNumber("FFFFFFFFh") mustBe "0xFFFFFFFF"
        cStyleNumber("0h") mustBe "0"
        cStyleNumber("00000000") mustBe "0"
        // Decimals, enum names and quoted strings aren't touched.
        cStyleNumber("42") mustBe "42"
        cStyleNumber("DSP_REVISION_FIRST") mustBe "DSP_REVISION_FIRST"
        cStyleNumber("\"kalimba\"") mustBe "\"kalimba\""
    }

    @Test
    fun `a long double decimal takes the L suffix, NaN and infinities stay bare`() {
        longDoubleLiteral("1.5") mustBe "1.5L"
        longDoubleLiteral("-2.0E-10") mustBe "-2.0E-10L"
        longDoubleLiteral("NaN") mustBe "NaN"
        longDoubleLiteral("Infinity") mustBe "Infinity"
    }
}
