package ghistabs.scan

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Blanking has to keep every offset and newline, or every line number downstream is wrong. */
class TextTest {
    private fun blanked(text: String) = String(text.stripCommentsAndLiterals())

    @Test
    fun `comments and literals go, positions stay`() {
        val src = "int a; /* } \n } */ char c = '}'; // }\nint b;"
        blanked(src) mustBe "int a;      \n      char c =    ;     \nint b;"
    }

    @Test
    fun `a line comment continues past a backslash newline`() {
        blanked("// x \\\n } { \nint b;") mustBe "      \n     \nint b;"
    }

    /** An apostrophe that is not a literal — `#error don't` — must not swallow the rest of the file. */
    @Test
    fun `an unterminated literal stops at its own line`() {
        blanked("#error don't \nint b;") mustBe "#error don   \nint b;"
    }
}
