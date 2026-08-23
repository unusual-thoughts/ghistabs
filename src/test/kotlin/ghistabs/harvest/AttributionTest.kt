package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.parse.HeaderFile
import ghistabs.parse.SourceFile
import ghistabs.test.mustBe
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
        cat.category mustBe CategoryPath("/std/string")
    }

    @Test
    fun stdlibMingwStdint() {
        val cat = attr.keyFor("int32_t", srcs("/usr/include/mingw/stdint.h"))
        cat.category mustBe CategoryPath("/std/stdint")
    }

    @Test
    fun stdlibSkipsBitsIntermediate() {
        // bits/ is a known intermediate dir — skipped, basename comes from the next segment
        val cat = attr.keyFor("vector_base", srcs("/usr/include/c++/3.4.4/bits/stl_vector.h"))
        cat.category mustBe CategoryPath("/std/stl_vector")
    }

    @Test
    fun stdlibWithOneIntermediateDir() {
        val cat = attr.keyFor("Foo", srcs("/usr/local/mingw/stdint.h"))
        cat.category mustBe CategoryPath("/std/stdint")
    }

    // --- Single source ------------------------------------------------------

    @Test
    fun singleHeaderSourcePreservesFullPath() {
        val cat = attr.keyFor("Foo", srcs("/proj/include/foo.h"))
        cat.category mustBe CategoryPath("/proj/include/foo.h")
    }

    @Test
    fun singleCuSourcePreservesFullPath() {
        val cat = attr.keyFor("LocalThing", srcs("/proj/src/main.cpp"))
        cat.category mustBe CategoryPath("/proj/src/main.cpp")
    }

    @Test
    fun normalizesDotDotInPath() {
        val cat = attr.keyFor("Foo", srcs("/proj/src/../include/foo.h"))
        cat.category mustBe CategoryPath("/proj/include/foo.h")
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
        attr.keyFor("Foo", defSources).category mustBe CategoryPath("/proj/include/foo.h")
    }

    // --- Real-header preference --------------------------------------------

    @Test
    fun realHeaderWinsOverFakeHeaderSibling() {
        // .cpp HeaderSources happen when gcc BINCL's a sibling CU (the
        // `inst.cpp` included by other CUs). A real .h beats the fake header.
        val sources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/inst.cpp", checksum = 1, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/parse.cpp", checksum = 2, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/include/inst.h", checksum = 3, originatingCu = null)),
        )
        attr.keyFor("SomeInst", sources).category mustBe CategoryPath("/proj/include/inst.h")
    }

    @Test
    fun realHeaderWinsOverCu() {
        // b2Hull-style: mostly CUSources, one real .h header.
        val sources = setOf(
            SourceFile.CUSource("/proj/a.cpp"),
            SourceFile.CUSource("/proj/b.cpp"),
            SourceFile.HeaderSource(HeaderFile("/proj/include/collision.h", checksum = 0, originatingCu = null)),
        )
        attr.keyFor("b2Hull", sources).category mustBe CategoryPath("/proj/include/collision.h")
    }

    @Test
    fun lexFirstAmongMultipleRealHeaders() {
        val sources = setOf(
            SourceFile.HeaderSource(HeaderFile("/proj/include/zeta.h", checksum = 0, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/include/alpha.h", checksum = 0, originatingCu = null)),
        )
        attr.keyFor("Foo", sources).category mustBe CategoryPath("/proj/include/alpha.h")
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
        attr.keyFor("basic_string", sources).category mustBe CategoryPath("/std/basic_string")
    }

    @Test
    fun allFakeHeadersFallBackToMultiBucket() {
        // bouniaf case: two .cpp HeaderSources, no real header → /multi.
        val sources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/inst.cpp", checksum = 1, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/parse.cpp", checksum = 2, originatingCu = null)),
        )
        attr.keyFor("SomeInst", sources).category mustBe CategoryPath("/proj/inst.cpp/multi")
    }

    // --- Multi-source -------------------------------------------------------

    @Test
    fun multiSourceUsesLexFirstPlusMulti() {
        val cat = attr.keyFor("Shared", srcs("/proj/a.cpp", "/proj/b.cpp"))
        cat.category mustBe CategoryPath("/proj/a.cpp/multi")
    }

    @Test
    fun multiSourceTemplateInstantiation() {
        val cat = attr.keyFor("vector<int,allocator<int>>", srcs("/proj/b.cpp", "/proj/a.cpp"))
        cat.category mustBe CategoryPath("/proj/a.cpp/multi")
    }

    @Test
    fun multiSourceFakeHeadersOnlyPicksLexFirstPlusMulti() {
        // Two .cpp HeaderSources (gcc BINCL'd siblings). No real headers, no CUs.
        val sources = setOf<SourceFile>(
            SourceFile.HeaderSource(HeaderFile("/proj/zeta.cpp", checksum = 1, originatingCu = null)),
            SourceFile.HeaderSource(HeaderFile("/proj/alpha.cpp", checksum = 2, originatingCu = null)),
        )
        attr.keyFor("Foo", sources).category mustBe CategoryPath("/proj/alpha.cpp/multi")
    }

    // --- Project-prefix stripping ------------------------------------------

    @Test
    fun projectPrefixStrippedFromSourcePath() {
        val a = Attribution(commonProjectPrefix = "/xml/box2d")
        val cat = a.keyFor("b2Hull", srcs("/xml/box2d/src/../include/box2d/collision.h"))
        cat.category mustBe CategoryPath("/include/box2d/collision.h")
    }

    @Test
    fun projectPrefixDoesNotStripStdlibPaths() {
        // stdlib remapping still wins; project prefix doesn't apply to /usr/include/...
        val a = Attribution(commonProjectPrefix = "/xml/box2d")
        val cat = a.keyFor("basic_string", srcs("/usr/include/c++/3.4.4/string"))
        cat.category mustBe CategoryPath("/std/string")
    }

    @Test
    fun commonProjectPrefixHelperFindsLcp() {
        val sources = listOf<SourceFile>(
            SourceFile.CUSource("/xml/box2d/samples/car.cpp"),
            SourceFile.CUSource("/xml/box2d/samples/donut.cpp"),
            SourceFile.CUSource("/xml/box2d/src/body.c"),
        )
        commonProjectPrefix(sources) mustBe "/xml/box2d"
    }

    @Test
    fun commonProjectPrefixIgnoresHeaders() {
        // Headers can live outside the project root; LCP is computed from CUSources only.
        val sources = listOf(
            SourceFile.CUSource("/xml/box2d/samples/car.cpp"),
            SourceFile.CUSource("/xml/box2d/samples/donut.cpp"),
            SourceFile.HeaderSource(HeaderFile("/usr/include/c++/3.4.4/string", checksum = 0, originatingCu = null)),
        )
        commonProjectPrefix(sources) mustBe "/xml/box2d/samples"
    }

    // --- Diagnostic traces --------------------------------------------------

    @Test
    fun traceRecordedOnStdRoute() {
        val diag = StabsDiagnostics()
        val cat = attr.keyFor("basic_string", srcs("/usr/include/c++/3.4.4/string"), diag)
        cat.category mustBe CategoryPath("/std/string")
        val traces = diag.snapshotAttributionTraces()
        traces.size mustBe 1
        traces[0].typeName mustBe "basic_string"
        traces[0].routedTo mustBe "/std/string"
    }

    @Test
    fun traceCappedAt200() {
        val diag = StabsDiagnostics()
        repeat(250) { i ->
            attr.keyFor("Type$i", srcs("/usr/include/c++/3.4.4/string$i"), diag)
        }
        val traces = diag.snapshotAttributionTraces()
        traces.size.mustBe(200, "Traces should be capped at 200")
        diag["attribution-routed-std"].mustBe(250L, "Counter should track all 250 calls")
    }

    // --- Windows drive-letter paths ----------------------------------------

    @Test
    fun windowsDriveLetterStrippedFromCuPath() {
        val cat = attr.keyFor("Foo", srcs("E:/dev/code/apps/sink/main.cpp"))
        cat.category mustBe CategoryPath("/dev/code/apps/sink/main.cpp")
    }

    @Test
    fun windowsDriveLetterStrippedFromHeaderPath() {
        val cat = attr.keyFor("Foo", srcs("c:/proj/lib/inc/widget.h"))
        cat.category mustBe CategoryPath("/proj/lib/inc/widget.h")
    }

    @Test
    fun aToolchainCHeaderRoutesToStd() {
        // `c:/mingw/include/stdint.h` nests the include root under the toolchain rather than the
        // other way round (`/usr/include/c++/…`), and used to miss the marker entirely — so mingw's
        // libc counted as a possible home for a user type. It is no more one than <vector> is.
        val cat = attr.keyFor("Foo", srcs("c:/mingw/include/stdint.h"))
        cat.category mustBe CategoryPath("/std/stdint")
    }

    @Test
    fun commonProjectPrefixStripsWindowsDriveLetter() {
        val sources = listOf<SourceFile>(
            SourceFile.CUSource("E:/dev/code/apps/sink/main.cpp"),
            SourceFile.CUSource("E:/dev/code/apps/sink/audio.cpp"),
        )
        commonProjectPrefix(sources) mustBe "/dev/code/apps/sink"
    }

    @Test
    fun windowsPathWithProjectPrefixStripped() {
        val sources = listOf<SourceFile>(
            SourceFile.CUSource("E:/dev/code/apps/sink/main.cpp"),
            SourceFile.CUSource("E:/dev/code/apps/sink/audio.cpp"),
        )
        val prefix = commonProjectPrefix(sources)
        val a = Attribution(commonProjectPrefix = prefix)
        val cat = a.keyFor("Foo", srcs("E:/dev/code/apps/sink/main.cpp"))
        cat.category mustBe CategoryPath("/main.cpp")
    }

    // --- Stdlib false positives --------------------------------------------

    @Test
    fun noFalsePositiveOnProjectCxxDir() {
        val cat = attr.keyFor("Foo", srcs("/proj/src/c++_helpers/foo.cpp"))
        cat.category mustBe CategoryPath("/proj/src/c++_helpers/foo.cpp")
    }

    @Test
    fun noFalsePositiveOnUsrLocalProj() {
        // Two intermediate dirs after /usr/ (local + myproj) — outside the regex's allowance.
        val cat = attr.keyFor("Foo", srcs("/usr/local/myproj/c++_helpers/foo.cpp"))
        cat.category mustBe CategoryPath("/usr/local/myproj/c++_helpers/foo.cpp")
    }
}
