package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.parse.HeaderFile
import ghistabs.parse.SourceFile
import org.junit.jupiter.api.Assertions.assertEquals
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

class AttributionTest {
    // No project prefix by default; tests use absolute paths.
    private val attr = Attribution()

    // --- Stdlib routing -----------------------------------------------------

    @Test
    fun stdlibCppStringHeader() {
        val cat = attr.keyFor("basic_string", srcs("/usr/include/c++/3.4.4/string"))
        assertEquals(CategoryPath("/std/string"), cat.category)
    }

    @Test
    fun stdlibMingwStdint() {
        val cat = attr.keyFor("int32_t", srcs("/usr/include/mingw/stdint.h"))
        assertEquals(CategoryPath("/std/stdint"), cat.category)
    }

    @Test
    fun stdlibSkipsBitsIntermediate() {
        // bits/ is a known intermediate dir — skipped, basename comes from the next segment
        val cat = attr.keyFor("vector_base", srcs("/usr/include/c++/3.4.4/bits/stl_vector.h"))
        assertEquals(CategoryPath("/std/stl_vector"), cat.category)
    }

    @Test
    fun stdlibWithOneIntermediateDir() {
        val cat = attr.keyFor("Foo", srcs("/usr/local/mingw/stdint.h"))
        assertEquals(CategoryPath("/std/stdint"), cat.category)
    }

    // --- Single source ------------------------------------------------------

    @Test
    fun singleHeaderSourcePreservesFullPath() {
        val cat = attr.keyFor("Foo", srcs("/proj/include/foo.h"))
        assertEquals(CategoryPath("/proj/include/foo.h"), cat.category)
    }

    @Test
    fun singleCuSourcePreservesFullPath() {
        val cat = attr.keyFor("LocalThing", srcs("/proj/src/main.cpp"))
        assertEquals(CategoryPath("/proj/src/main.cpp"), cat.category)
    }

    @Test
    fun normalizesDotDotInPath() {
        val cat = attr.keyFor("Foo", srcs("/proj/src/../include/foo.h"))
        assertEquals(CategoryPath("/proj/include/foo.h"), cat.category)
    }

    @Test
    fun multipleHeaderSourcesForSamePathCollapse() {
        // Forward-EXCL can produce distinct HeaderFile instances for the same
        // physical header. They share `.filename` so attribution collapses them.
        val originator = SourceFile.CUSource("/proj/src/a.cpp")
        val defSources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/include/foo.h", checksum = 1L, originatingCu = originator)),
            SourceFile.HeaderSource(HeaderFile("/proj/include/foo.h", checksum = 2L, originatingCu = null)),
        )
        assertEquals(CategoryPath("/proj/include/foo.h"), attr.keyFor("Foo", defSources).category)
    }

    // --- Real-header preference --------------------------------------------

    @Test
    fun realHeaderWinsOverFakeHeaderSibling() {
        // .cpp HeaderSources happen when gcc BINCL's a sibling CU (xapasmcsr's
        // `inst.cpp` included by other CUs). A real .h beats the fake header.
        val sources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/inst.cpp", checksum = 1, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/parse.cpp", checksum = 2, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/include/inst.h", checksum = 3, originatingCu = null)),
        )
        assertEquals(CategoryPath("/proj/include/inst.h"), attr.keyFor("XapArgInst", sources).category)
    }

    @Test
    fun realHeaderWinsOverCu() {
        // b2Hull-style: mostly CUSources, one real .h header.
        val sources = setOf(
            SourceFile.CUSource("/proj/a.cpp"),
            SourceFile.CUSource("/proj/b.cpp"),
            SourceFile.HeaderSource(HeaderFile("/proj/include/collision.h", checksum = 0, originatingCu = null)),
        )
        assertEquals(CategoryPath("/proj/include/collision.h"), attr.keyFor("b2Hull", sources).category)
    }

    @Test
    fun lexFirstAmongMultipleRealHeaders() {
        val sources = setOf(
            SourceFile.HeaderSource(HeaderFile("/proj/include/zeta.h", checksum = 0, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/include/alpha.h", checksum = 0, originatingCu = null)),
        )
        assertEquals(CategoryPath("/proj/include/alpha.h"), attr.keyFor("Foo", sources).category)
    }

    @Test
    fun tccHeaderCountsAsRealHeader() {
        // libstdc++ template impls (`.tcc`) — should be treated as headers.
        val sources = setOf(
            SourceFile.HeaderSource(HeaderFile("/usr/include/c++/3.4.4/bits/basic_string.tcc", 0, null)),
            SourceFile.CUSource("/proj/a.cpp"),
        )
        // basic_string.tcc → /std/basic_string (stdlib remap wins first; this test
        // just confirms .tcc participates in the real-header pool by routing
        // through stdlib, not into the multi-source fallback).
        assertEquals(CategoryPath("/std/basic_string"), attr.keyFor("basic_string", sources).category)
    }

    @Test
    fun allFakeHeadersFallBackToMultiBucket() {
        // XapArgInst case: two .cpp HeaderSources, no real header → /multi.
        val sources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/inst.cpp", checksum = 1, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/parse.cpp", checksum = 2, originatingCu = null)),
        )
        assertEquals(CategoryPath("/proj/inst.cpp/multi"), attr.keyFor("XapArgInst", sources).category)
    }

    // --- Multi-source -------------------------------------------------------

    @Test
    fun multiSourceUsesLexFirstPlusMulti() {
        val cat = attr.keyFor("Shared", srcs("/proj/a.cpp", "/proj/b.cpp"))
        assertEquals(CategoryPath("/proj/a.cpp/multi"), cat.category)
    }

    @Test
    fun multiSourceTemplateInstantiation() {
        val cat = attr.keyFor("vector<int,allocator<int>>", srcs("/proj/b.cpp", "/proj/a.cpp"))
        assertEquals(CategoryPath("/proj/a.cpp/multi"), cat.category)
    }

    @Test
    fun multiSourceFakeHeadersOnlyPicksLexFirstPlusMulti() {
        // Two .cpp HeaderSources (gcc BINCL'd siblings). No real headers, no CUs.
        val sources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/zeta.cpp", checksum = 1, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/alpha.cpp", checksum = 2, originatingCu = null)),
        )
        assertEquals(CategoryPath("/proj/alpha.cpp/multi"), attr.keyFor("Foo", sources).category)
    }

    // --- Project-prefix stripping ------------------------------------------

    @Test
    fun projectPrefixStrippedFromSourcePath() {
        val a = Attribution(commonProjectPrefix = "/xml/box2d")
        val cat = a.keyFor("b2Hull", srcs("/xml/box2d/src/../include/box2d/collision.h"))
        assertEquals(CategoryPath("/include/box2d/collision.h"), cat.category)
    }

    @Test
    fun projectPrefixDoesNotStripStdlibPaths() {
        // stdlib remapping still wins; project prefix doesn't apply to /usr/include/...
        val a = Attribution(commonProjectPrefix = "/xml/box2d")
        val cat = a.keyFor("basic_string", srcs("/usr/include/c++/3.4.4/string"))
        assertEquals(CategoryPath("/std/string"), cat.category)
    }

    @Test
    fun commonProjectPrefixHelperFindsLcp() {
        val sources = listOf<SourceFile>(
            SourceFile.CUSource("/xml/box2d/samples/car.cpp"),
            SourceFile.CUSource("/xml/box2d/samples/donut.cpp"),
            SourceFile.CUSource("/xml/box2d/src/body.c"),
        )
        assertEquals("/xml/box2d", commonProjectPrefix(sources))
    }

    @Test
    fun commonProjectPrefixIgnoresHeaders() {
        // Headers can live outside the project root; LCP is computed from CUSources only.
        val sources = listOf(
            SourceFile.CUSource("/xml/box2d/samples/car.cpp"),
            SourceFile.CUSource("/xml/box2d/samples/donut.cpp"),
            SourceFile.HeaderSource(HeaderFile("/usr/include/c++/3.4.4/string", checksum = 0, originatingCu = null)),
        )
        assertEquals("/xml/box2d/samples", commonProjectPrefix(sources))
    }

    // --- Diagnostic traces --------------------------------------------------

    @Test
    fun traceRecordedOnStdRoute() {
        val diag = StabsDiagnostics()
        val cat = attr.keyFor("basic_string", srcs("/usr/include/c++/3.4.4/string"), diag)
        assertEquals(CategoryPath("/std/string"), cat.category)
        val traces = diag.snapshotAttributionTraces()
        assertEquals(1, traces.size)
        assertEquals("basic_string", traces[0].typeName)
        assertEquals("/std/string", traces[0].routedTo)
    }

    @Test
    fun traceCappedAt200() {
        val diag = StabsDiagnostics()
        repeat(250) { i ->
            attr.keyFor("Type$i", srcs("/usr/include/c++/3.4.4/string$i"), diag)
        }
        val traces = diag.snapshotAttributionTraces()
        assertEquals(200, traces.size, "Traces should be capped at 200")
        assertEquals(250L, diag["attribution-routed-std"], "Counter should track all 250 calls")
    }

    // --- Windows drive-letter paths ----------------------------------------

    @Test
    fun windowsDriveLetterStrippedFromCuPath() {
        val cat = attr.keyFor("Foo", srcs("E:/work/cc/adk/apps/sink/main.cpp"))
        assertEquals(CategoryPath("/work/cc/adk/apps/sink/main.cpp"), cat.category)
    }

    @Test
    fun windowsDriveLetterStrippedFromHeaderPath() {
        val cat = attr.keyFor("Foo", srcs("c:/mingw/include/stdint.h"))
        assertEquals(CategoryPath("/mingw/include/stdint.h"), cat.category)
    }

    @Test
    fun commonProjectPrefixStripsWindowsDriveLetter() {
        val sources = listOf<SourceFile>(
            SourceFile.CUSource("E:/work/cc/adk/apps/sink/main.cpp"),
            SourceFile.CUSource("E:/work/cc/adk/apps/sink/audio.cpp"),
        )
        assertEquals("/work/cc/adk/apps/sink", commonProjectPrefix(sources))
    }

    @Test
    fun windowsPathWithProjectPrefixStripped() {
        val sources = listOf<SourceFile>(
            SourceFile.CUSource("E:/work/cc/adk/apps/sink/main.cpp"),
            SourceFile.CUSource("E:/work/cc/adk/apps/sink/audio.cpp"),
        )
        val prefix = commonProjectPrefix(sources)
        val a = Attribution(commonProjectPrefix = prefix)
        val cat = a.keyFor("Foo", srcs("E:/work/cc/adk/apps/sink/main.cpp"))
        assertEquals(CategoryPath("/main.cpp"), cat.category)
    }

    // --- Stdlib false positives --------------------------------------------

    @Test
    fun noFalsePositiveOnProjectCxxDir() {
        val cat = attr.keyFor("Foo", srcs("/proj/src/c++_helpers/foo.cpp"))
        assertEquals(CategoryPath("/proj/src/c++_helpers/foo.cpp"), cat.category)
    }

    @Test
    fun noFalsePositiveOnUsrLocalProj() {
        // Two intermediate dirs after /usr/ (local + myproj) — outside the regex's allowance.
        val cat = attr.keyFor("Foo", srcs("/usr/local/myproj/c++_helpers/foo.cpp"))
        assertEquals(CategoryPath("/usr/local/myproj/c++_helpers/foo.cpp"), cat.category)
    }
}
