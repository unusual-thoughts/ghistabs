package ghistabs.source

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Blanking has to keep every offset and newline, or every line number downstream is wrong. */
class TextTest {
    private fun blanked(text: String) = String(scannable(text))

    @Test
    fun `comments and literals go, positions stay`() {
        val src = "int a; /* } \n } */ char c = '}'; // }\nint b;"
        assertEquals("int a;      \n      char c =    ;     \nint b;", blanked(src))
    }

    @Test
    fun `a line comment continues past a backslash newline`() {
        assertEquals("      \n     \nint b;", blanked("// x \\\n } { \nint b;"))
    }

    /** An apostrophe that is not a literal — `#error don't` — must not swallow the rest of the file. */
    @Test
    fun `an unterminated literal stops at its own line`() {
        assertEquals("#error don   \nint b;", blanked("#error don't \nint b;"))
    }
}
