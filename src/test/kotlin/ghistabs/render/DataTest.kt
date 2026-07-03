package ghistabs.render

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Pins [cStyleNumber]: Ghidra's `<hex>h` / zero-run listing format → C literals; other reprs pass through. */
class DataTest {
    @Test
    fun `hex-h becomes 0x, zero runs become 0, other reprs untouched`() {
        assertEquals("0xDEADCAFE", cStyleNumber("DEADCAFEh"))
        assertEquals("0x5", cStyleNumber("5h"))
        assertEquals("0xFFFFFFFF", cStyleNumber("FFFFFFFFh"))
        assertEquals("0", cStyleNumber("0h"))
        assertEquals("0", cStyleNumber("00000000"))
        // Decimals, enum names and quoted strings aren't touched.
        assertEquals("42", cStyleNumber("42"))
        assertEquals("DSP_REVISION_FIRST", cStyleNumber("DSP_REVISION_FIRST"))
        assertEquals("\"kalimba\"", cStyleNumber("\"kalimba\""))
    }
}
