package ghistabs.builder

import ghidra.program.model.data.CategoryPath
import ghistabs.diag.StabsDiagnostics
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

// NOTE: This file imports ghidra.program.model.data.CategoryPath because Attribution.categoryFor
// returns CategoryPath directly. Per testing-convention.md this is a Kind 1 violation; tracked
// for future refactor (extract pure-string core from Attribution, adapt to CategoryPath at the boundary).
// Until then, this file is treated as a tolerated exception.
class AttributionTest {
    @Test fun testCppStdBasename() {
        val cat = Attribution.categoryFor("basic_string", setOf("/usr/include/c++/3.4.4/string"))
        assertEquals(CategoryPath("/std/string"), cat)
    }

    @Test fun testMingwStdBasename() {
        val cat = Attribution.categoryFor("int32_t", setOf("/usr/include/mingw/stdint.h"))
        assertEquals(CategoryPath("/std/stdint"), cat)
    }

    @Test fun testSingleHeaderCU() {
        val cat = Attribution.categoryFor("Foo", setOf("/proj/include/foo.h"))
        assertEquals(CategoryPath("/foo"), cat)
    }

    @Test fun testSingleSourceCU() {
        val cat = Attribution.categoryFor("LocalThing", setOf("/proj/src/main.cpp"))
        assertEquals(CategoryPath("/main"), cat)
    }

    @Test fun testMultiCUCleanName() {
        val cat = Attribution.categoryFor("Shared", setOf("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/headers-untracked/Shared.h"), cat)
    }

    @Test fun testMultiCULexicalFirstCanonical() {
        // Two CUs; canonical (lex-first) is "a"
        val cat = Attribution.categoryFor("vector<int,allocator<int>>", setOf("/proj/b.cpp", "/proj/a.cpp"))
        assertEquals(CategoryPath("/a/instantiations"), cat)
    }

    @Test fun testMultiCUUncleanStartsWithUnderscore() {
        val cat = Attribution.categoryFor("__internal", setOf("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/a/instantiations"), cat)
    }

    @Test fun testMultiCUBuiltinNameUnclean() {
        val cat = Attribution.categoryFor("int", setOf("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/a/instantiations"), cat)
    }

    @Test fun testTraceRecordedOnStdRoute() {
        // Use a genuine stdlib type that's not in the override list
        val diag = StabsDiagnostics()
        val cat =
            Attribution.categoryFor(
                "basic_string",
                setOf("/usr/include/c++/3.4.4/string"),
                diag,
            )
        assertEquals(CategoryPath("/std/string"), cat)
        val traces = diag.snapshotAttributionTraces()
        assertEquals(1, traces.size)
        assertEquals("basic_string", traces[0].typeName)
        assertEquals("/usr/include/c++/3.4.4/string", traces[0].matchedCU)
        assertEquals("/std/string", traces[0].routedTo)
    }

    @Test fun testTraceCappedAt200() {
        val diag = StabsDiagnostics()
        repeat(250) { i ->
            Attribution.categoryFor(
                "Type$i",
                setOf("/usr/include/c++/3.4.4/string$i"),
                diag,
            )
        }
        val traces = diag.snapshotAttributionTraces()
        assertEquals(200, traces.size, "Traces should be capped at 200")
        assertEquals(250L, diag["attribution-routed-std"], "Counter should track all 250 calls")
    }

    @Test fun testNoFalsePositiveOnProjectCxxDir() {
        // Path with c++ as a directory name should NOT route to /std/
        val cat = Attribution.categoryFor("Foo", setOf("/proj/src/c++_helpers/foo.cpp"))
        assertEquals(CategoryPath("/foo"), cat)
    }

    @Test fun testRealStdlibStillMatches() {
        // Real stdlib paths must still match the tightened regex
        val cat = Attribution.categoryFor("basic_string", setOf("/usr/include/c++/3.4.4/string"))
        assertEquals(CategoryPath("/std/string"), cat)
    }

    @Test fun testbouniafOverrideRoutesToProj() {
        // bouniaf should route to /proj/ regardless of CU path
        val diag = StabsDiagnostics()
        val cat =
            Attribution.categoryFor(
                "bouniaf",
                setOf("/anywhere/at/all/string"),
                diag,
            )
        assertTrue(cat.toString().startsWith("/proj"), "bouniaf should route to /proj/")
        assertEquals(1L, diag["attribution-override"], "Override counter should increment")
    }

    @Test fun testGenuineStdTypesStillRouteToStd() {
        // Genuine stdlib types NOT in override list should still route to /std/
        val cat = Attribution.categoryFor("vector", setOf("/usr/include/c++/3.4.4/vector"))
        assertEquals(CategoryPath("/std/vector"), cat)
    }

    @Test fun testNoFalsePositiveOnUsrLocalProj() {
        // A CU path like /usr/local/myproj/c++_helpers/foo.cpp should NOT route to /std/
        // because there are two intermediate dirs after /usr/: "local" and "myproj"
        // The regex /(usr|lib|include)(/[^/]+)?/(mingw|cygwin|c\+\+|bits)/ only allows one
        val cat = Attribution.categoryFor("Foo", setOf("/usr/local/myproj/c++_helpers/foo.cpp"))
        assertEquals(CategoryPath("/foo"), cat)
    }

    @Test fun testStdlibWithOneIntermediateDir() {
        // /usr/local/mingw/ should still match (one intermediate dir "local")
        val cat = Attribution.categoryFor("Foo", setOf("/usr/local/mingw/foo.h"))
        assertEquals(CategoryPath("/std/mingw"), cat)
    }
}
