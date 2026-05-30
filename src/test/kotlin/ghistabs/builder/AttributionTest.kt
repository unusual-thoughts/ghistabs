package ghistabs.builder

import ghidra.program.model.data.CategoryPath
import ghistabs.diag.StabsDiagnostics
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

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
        val diag = StabsDiagnostics()
        val cat =
            Attribution.categoryFor(
                "bouniaf",
                setOf("/usr/include/c++/3.4.4/string"),
                diag,
            )
        assertEquals(CategoryPath("/std/string"), cat)
        val traces = diag.snapshotAttributionTraces()
        assertEquals(1, traces.size)
        assertEquals("bouniaf", traces[0].typeName)
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
}
