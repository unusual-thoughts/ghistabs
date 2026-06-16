package ghistabs.parser

import ghidra.program.model.data.CategoryPath
import ghistabs.diag.StabsDiagnostics
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Path-only helper for tests. Attribution only inspects `.filename` on each
 * SourceFile, so route every path through the CU branch with the path used
 * as both CU name and filename. For header-only paths a HeaderSource is
 * equivalent — neither branch carries a checksum/instance.
 */
private fun src(path: String): SourceFile =
    if (path.endsWith(".h") || path.endsWith(".hpp") || path.endsWith(".hh") || path.contains("/include/")) {
        SourceFile.HeaderSource(HeaderFile(filename = path, checksum = 0, originatingCu = SourceFile.CUSource(path)))
    } else {
        SourceFile.CUSource(path)
    }

private fun srcs(vararg paths: String): Set<SourceFile> = paths.map(::src).toSet()

// NOTE: This file imports ghidra.program.model.data.CategoryPath because Attribution.categoryFor
// returns CategoryPath directly. Per testing-convention.md this is a Kind 1 violation; tracked
// for future refactor (extract pure-string core from Attribution, adapt to CategoryPath at the boundary).
// Until then, this file is treated as a tolerated exception.
class AttributionTest {
    @Test
    fun testCppStdBasename() {
        val cat = Attribution.categoryFor("basic_string", srcs("/usr/include/c++/3.4.4/string"))
        assertEquals(CategoryPath("/std/string"), cat)
    }

    @Test
    fun testMingwStdBasename() {
        val cat = Attribution.categoryFor("int32_t", srcs("/usr/include/mingw/stdint.h"))
        assertEquals(CategoryPath("/std/stdint"), cat)
    }

    @Test
    fun testSingleHeaderCU() {
        // D2: HeaderSource defs route to /headers/<basename>/ regardless of CU count.
        val cat = Attribution.categoryFor("Foo", srcs("/proj/include/foo.h"))
        assertEquals(CategoryPath("/headers/foo"), cat)
    }

    @Test
    fun testMultiHeaderSameBasenameRoutesToHeaders() {
        // Two HeaderSource entries with the same filename basename but distinct
        // checksums — D1 forward-EXCL placeholders can produce distinct
        // HeaderFile instances for the same header; attribution must still
        // converge on a single /headers/<basename>/ category.
        val originator = SourceFile.CUSource("/proj/src/a.cpp")
        val defSources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/include/foo.h", checksum = 1L, originatingCu = originator)),
            SourceFile.HeaderSource(HeaderFile("/proj/include/foo.h", checksum = 2L, originatingCu = null)),
        )
        assertEquals(CategoryPath("/headers/foo"), Attribution.categoryFor("Foo", defSources))
    }

    @Test
    fun testSingleSourceCU() {
        val cat = Attribution.categoryFor("LocalThing", srcs("/proj/src/main.cpp"))
        assertEquals(CategoryPath("/main"), cat)
    }

    @Test
    fun testMultiCUCleanName() {
        val cat = Attribution.categoryFor("Shared", srcs("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/headers-untracked/Shared.h"), cat)
    }

    @Test
    fun testMultiCULexicalFirstCanonical() {
        // Two CUs; canonical (lex-first) is "a"
        val cat = Attribution.categoryFor("vector<int,allocator<int>>", srcs("/proj/b.cpp", "/proj/a.cpp"))
        assertEquals(CategoryPath("/a/instantiations"), cat)
    }

    @Test
    fun testMultiCUUncleanStartsWithUnderscore() {
        val cat = Attribution.categoryFor("__internal", srcs("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/a/instantiations"), cat)
    }

    @Test
    fun testMultiCUBuiltinNameUnclean() {
        val cat = Attribution.categoryFor("int", srcs("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/a/instantiations"), cat)
    }

    @Test
    fun testTraceRecordedOnStdRoute() {
        // Use a genuine stdlib type that's not in the override list
        val diag = StabsDiagnostics()
        val cat =
            Attribution.categoryFor(
                "basic_string",
                srcs("/usr/include/c++/3.4.4/string"),
                diag,
            )
        assertEquals(CategoryPath("/std/string"), cat)
        val traces = diag.snapshotAttributionTraces()
        assertEquals(1, traces.size)
        assertEquals("basic_string", traces[0].typeName)
        assertEquals("/usr/include/c++/3.4.4/string", traces[0].matchedCU.filename)
        assertEquals("/std/string", traces[0].routedTo)
    }

    @Test
    fun testTraceCappedAt200() {
        val diag = StabsDiagnostics()
        repeat(250) { i ->
            Attribution.categoryFor(
                "Type$i",
                srcs("/usr/include/c++/3.4.4/string$i"),
                diag,
            )
        }
        val traces = diag.snapshotAttributionTraces()
        assertEquals(200, traces.size, "Traces should be capped at 200")
        assertEquals(250L, diag["attribution-routed-std"], "Counter should track all 250 calls")
    }

    @Test
    fun testNoFalsePositiveOnProjectCxxDir() {
        // Path with c++ as a directory name should NOT route to /std/
        val cat = Attribution.categoryFor("Foo", srcs("/proj/src/c++_helpers/foo.cpp"))
        assertEquals(CategoryPath("/foo"), cat)
    }

    @Test
    fun testRealStdlibStillMatches() {
        // Real stdlib paths must still match the tightened regex
        val cat = Attribution.categoryFor("basic_string", srcs("/usr/include/c++/3.4.4/string"))
        assertEquals(CategoryPath("/std/string"), cat)
    }

    @Test
    fun testXapArgInstOverrideRoutesToProj() {
        // XapArgInst should route to /proj/ regardless of CU path
        val diag = StabsDiagnostics()
        val cat =
            Attribution.categoryFor(
                "XapArgInst",
                srcs("/anywhere/at/all/string"),
                diag,
            )
        assertTrue(cat.toString().startsWith("/proj"), "XapArgInst should route to /proj/")
        assertEquals(1L, diag["attribution-override"], "Override counter should increment")
    }

    @Test
    fun testGenuineStdTypesStillRouteToStd() {
        // Genuine stdlib types NOT in override list should still route to /std/
        val cat = Attribution.categoryFor("vector", srcs("/usr/include/c++/3.4.4/vector"))
        assertEquals(CategoryPath("/std/vector"), cat)
    }

    @Test
    fun testNoFalsePositiveOnUsrLocalProj() {
        // A CU path like /usr/local/myproj/c++_helpers/foo.cpp should NOT route to /std/
        // because there are two intermediate dirs after /usr/: "local" and "myproj"
        // The regex /(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/ only allows one
        val cat = Attribution.categoryFor("Foo", srcs("/usr/local/myproj/c++_helpers/foo.cpp"))
        assertEquals(CategoryPath("/foo"), cat)
    }

    @Test
    fun testStdlibWithOneIntermediateDir() {
        // /usr/local/mingw/ should still match (one intermediate dir "local")
        // The basename is extracted from the path after the marker, so /usr/local/mingw/stdint.h → /std/stdint
        val cat = Attribution.categoryFor("Foo", srcs("/usr/local/mingw/stdint.h"))
        assertEquals(CategoryPath("/std/stdint"), cat)
    }
}
