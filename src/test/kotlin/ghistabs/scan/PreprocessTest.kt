package ghistabs.scan

import ghistabs.ECHOES_DROPPED_LINES
import ghistabs.diagnose.CapturingSink
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
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

    @BeforeEach
    fun requirePreprocessorDroppedLines() =
        assumeTrue(ECHOES_DROPPED_LINES, "Ghidra below 11.3 does not echo dropped lines")

    @Test
    fun `the arm that did not compile is reported at its own line numbers`() {
        val hdr = write("inc/hdr.h", header)
        val unit = write("main.cpp", """#include "hdr.h"${'\n'}int main() { return sized(2); }""")

        val dropped = Preprocessed.of(unit, listOf(root.resolve("inc").toFile()), CapturingSink())

        // L9 is `inline int locked()`, inside the `#ifdef _REENTRANT` nothing defined — and it is
        // the ninth line of the header, not of the preprocessor's own output, which has neither the
        // three-line comment nor `n * WIDTH`.
        dropped?.get(hdr) mustBe setOf(9)
        hdr.readLines()[8] mustBe "inline int locked() { return 1; }"
    }

    @Test
    fun `masking the dead arm leaves the live one to name the line`() {
        val hdr = write("inc/hdr.h", header)
        val unit = write("main.cpp", """#include "hdr.h"${'\n'}int main() { return sized(2); }""")
        val dropped = Preprocessed.of(unit, listOf(root.resolve("inc").toFile()), CapturingSink())

        val indexes = SourceIndexes { dropped?.get(it).orEmpty() }
        indexes[hdr].enclosing(11)?.name mustBe "unlocked"
        indexes[hdr].enclosing(9).mustBeNull("the arm that did not compile defines nothing")
    }

    /** What the render asks for: every mapped unit, one answer per header, no unit trusted alone. */
    @Test
    fun `dropped lines merge across the units that reached a header`() {
        val hdr = write("inc/hdr.h", header)
        val plain = write("plain.cpp", """#include "hdr.h"${'\n'}int a() { return sized(1); }""")
        val reentrant = write(
            "reentrant.cpp",
            """#define _REENTRANT${'\n'}#include "hdr.h"${'\n'}int b() { return sized(1); }""",
        )

        val dropped = Preprocessed.lines(
            listOf(plain, reentrant),
            listOf(root.resolve("inc").toFile()),
            CapturingSink(),
        )

        // L9 is the arm `plain.cpp` dropped, L11 the one `reentrant.cpp` dropped. Neither survives:
        // a header compiled both ways has no arm the scan can believe, and leaving both is the
        // unbalanced brace this is here to prevent.
        dropped(hdr) mustBe setOf(9, 11)
    }

    /** A source tarball has no generated `bits/c++config.h`; that must degrade, not throw. */
    @Test
    fun `an incomplete include environment is reported once and gives no answer`() {
        val unit = write("main.cpp", """#include "absent.h"${'\n'}int main() { return 0; }""")
        val sink = CapturingSink()

        Preprocessed.of(unit, listOf(File(root.toFile(), "inc")), sink) mustBe null
        sink.lines.must("the fallback to raw reading must be said once: ${sink.capturedOutput()}") {
            any { it.tag == "source-preprocess-incomplete" }
        }
    }
}
