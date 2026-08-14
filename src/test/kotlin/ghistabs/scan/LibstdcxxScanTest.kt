package ghistabs.scan

import ghistabs.diagnose.CapturingSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.io.File

/**
 * The scan against the headers it exists for: gcc 3.2.3's libstdc++, the tree `unbouniaf` was built
 * from. Synthetic C++ can be written to suit the scanner; these were not, and every construct that
 * has ever broken it — a licence block full of braces, a body on the same line as its head, a member
 * inside a class inside a namespace, an `#ifdef` around a specialisation — is in them already.
 *
 * Not vendored: `-PlibstdcxxInclude=<dir>`, else `~/git/gcc/libstdc++-v3/include`, else skipped.
 */
class LibstdcxxScanTest {
    private val include = System.getProperty("libstdcxxInclude").orEmpty().ifEmpty { DEFAULT }.let(::File)

    @BeforeEach
    fun requireCheckout() = assumeTrue(
        include.resolve("bits/stl_vector.h").isFile,
        "no libstdc++ 3.2.3 checkout at $include — set -PlibstdcxxInclude=<dir>",
    )

    /**
     * The two answers §44 tabulated, read off the real files. Both are members of a class template
     * nested in `namespace std`, with the body on the line after the head — the shape the head
     * reader has to walk back over, and the reason it cannot just take the line above the brace.
     */
    @Test
    fun `enclosing names the member a line falls in`() {
        val indexes = SourceIndexes()

        assertEquals("_M_deallocate", indexes[include.resolve("bits/stl_vector.h")].enclosing(123)?.name)
        assertEquals("_M_data", indexes[include.resolve("bits/basic_string.h")].enclosing(229)?.name)
    }

    /**
     * A real conditional, masked at the header's own line numbers. `cpp_type_traits.h` includes
     * nothing, so the preprocessor needs no environment beyond the header itself — which is what
     * makes this a unit test rather than a build.
     */
    @Test
    fun `the arm a compile dropped is masked in the header it came from`(@org.junit.jupiter.api.io.TempDir tmp: File) {
        val header = include.resolve("bits/cpp_type_traits.h")
        val unit = File(tmp, "main.cpp").apply {
            writeText("#include <bits/cpp_type_traits.h>\nint main() { return 0; }\n")
        }

        val dropped = Preprocessed.lines(listOf(unit), listOf(include), CapturingSink())(header)

        // `# ifdef _GLIBCPP_USE_WCHAR_T` at L138 guards the wchar_t specialisation on L139-146.
        // Nothing defined it, so those are the header's dropped lines — numbered as the file numbers
        // them, not as the preprocessor's own output does.
        assertEquals((139..146).toSet(), dropped)
        assertEquals("struct __is_integer<wchar_t>", header.readLines()[139].trim())
    }

    private companion object {
        val DEFAULT = File(System.getProperty("user.home"), "git/gcc/libstdc++-v3/include").path
    }
}
