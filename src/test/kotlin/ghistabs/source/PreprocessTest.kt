package ghistabs.source

import ghistabs.diagnose.CapturingSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText

/**
 * The preprocessor over a complete include environment, and what it does without one.
 *
 * The header is written with a licence block and a macro so the test exercises the two reasons the
 * stream's own positions cannot be used — comments removed, text expanded — rather than a shape
 * where a naive `#line` split would happen to work.
 */
class PreprocessTest {
    @TempDir
    lateinit var root: Path

    private fun write(relative: String, text: String) =
        root.resolve(relative).also { it.parent.createDirectories() }.also { it.writeText(text.trimIndent()) }.toFile()

    private val header = """
        /* licence
           block
           here */
        #ifndef HDR_H
        #define HDR_H
        #define WIDTH 4
        int sized(int n) { return n * WIDTH; }
        #ifdef _REENTRANT
        inline int locked() { return 1; }
        #else
        inline int unlocked() { return 0; }
        #endif
        #endif
    """

    @Test
    fun `the arm that did not compile is reported at its own line numbers`() {
        val hdr = write("inc/hdr.h", header)
        val unit = write("main.cpp", """#include "hdr.h"${'\n'}int main() { return sized(2); }""")

        val dropped = Preprocessed.of(unit, listOf(root.resolve("inc").toFile()), CapturingSink())

        // L9 is `inline int locked()`, inside the `#ifdef _REENTRANT` nothing defined — and it is
        // the ninth line of the header, not of the preprocessor's own output, which has neither the
        // three-line comment nor `n * WIDTH`.
        assertEquals(setOf(9), dropped?.get(hdr))
        assertEquals("inline int locked() { return 1; }", hdr.readLines()[8])
    }

    @Test
    fun `masking the dead arm leaves the live one to name the line`() {
        val hdr = write("inc/hdr.h", header)
        val unit = write("main.cpp", """#include "hdr.h"${'\n'}int main() { return sized(2); }""")
        val dropped = Preprocessed.of(unit, listOf(root.resolve("inc").toFile()), CapturingSink())

        val indexes = SourceIndexes { dropped?.get(it).orEmpty() }
        assertEquals("unlocked", indexes[hdr].enclosing(11)?.name)
        assertNull(indexes[hdr].enclosing(9), "the arm that did not compile defines nothing")
    }

    /** A source tarball has no generated `bits/c++config.h`; that must degrade, not throw. */
    @Test
    fun `an incomplete include environment is reported once and gives no answer`() {
        val unit = write("main.cpp", """#include "absent.h"${'\n'}int main() { return 0; }""")
        val sink = CapturingSink()

        assertNull(Preprocessed.of(unit, listOf(File(root.toFile(), "inc")), sink))
        assertTrue(
            sink.lines.any { it.tag == "source-preprocess-incomplete" },
            "the fallback to raw reading must be said once: ${sink.capturedOutput()}",
        )
    }
}
