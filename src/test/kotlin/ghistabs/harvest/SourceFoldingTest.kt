package ghistabs.harvest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** Spellings in, normalised paths out — the fold decides which spelling wins, the identity decides
 *  how it is written, and these assert the first against the second. */
private fun fold(vararg spellings: String) = foldSourcePaths(spellings.map(::sourceFileOf))
    .entries.associate { (raw, folded) -> raw.path to folded.path }

class SourceFoldingTest {
    @Test
    fun bareFoldsOntoItsFullPath() {
        // The bare `dspinfo.h` and its single full-path spelling collapse onto the full one — the
        // render writes a tree, so the directory the stabs know is worth keeping.
        val map = fold("dspinfo.h", "/work/include/dspinfo/dspinfo.h")
        assertEquals("/work/include/dspinfo/dspinfo.h", map.getValue("/dspinfo.h"))
        assertEquals("/work/include/dspinfo/dspinfo.h", map.getValue("/work/include/dspinfo/dspinfo.h"))
    }

    @Test
    fun sameHeaderUnderDifferentBuildRootsFolds() {
        // One physical header (`xvimage/image.h`) compiled in two build trees keeps its parent dir,
        // so every spelling folds onto one of them — the shallowest, being the least specific to a
        // single build root. Equal depth here, so the lexicographic tie-break decides.
        val map = fold(
            "image.h",
            "/jenkins/bluesuite/result/include/xvimage/image.h",
            "/work/devtools/result/include/xvimage/image.h",
        )
        for (i in map.keys) assertEquals("/jenkins/bluesuite/result/include/xvimage/image.h", map.getValue(i))
    }

    @Test
    fun equalDepthRootsPickTheSameOneEveryTime() {
        // Two roots at the same depth are equally true; the tie-break is lexicographic so the choice
        // cannot drift with the order the spellings were harvested in.
        val map = fold("/work/include/xvimage/image.h", "/jenkins/include/xvimage/image.h")
        val reversed = fold("/jenkins/include/xvimage/image.h", "/work/include/xvimage/image.h")
        for (i in map.keys) assertEquals("/jenkins/include/xvimage/image.h", map.getValue(i))
        assertEquals(map, reversed)
    }

    @Test
    fun headersSharingOnlyACommonParentNameDoNotMerge() {
        // mingw's `stdarg.h` and gcc's own both sit in an `include/`, which is why one directory of
        // agreement is not enough to call two paths the same file.
        val map = fold("c:/mingw/include/stdarg.h", "c:/mingw/lib/gcc-lib/mingw32/3.2.3/include/stdarg.h")
        for (i in map.keys) assertEquals(i, map.getValue(i))
    }

    @Test
    fun distinctHeadersSharingBasenameDoNotMerge() {
        // Different parent dirs → genuinely distinct files; the bare name is ambiguous, nothing folds.
        val map = fold("config.h", "/proj/moduleA/config.h", "/proj/moduleB/config.h")
        for (i in map.keys) assertEquals(i, map.getValue(i))
    }

    @Test
    fun aBareNameWithNoFullSpellingStaysBare() {
        // Nothing better is known about it. `packfile.cpp` is a CU and never has one.
        val map = fold("filesystemimage.h", "packfile.cpp")
        assertEquals("/filesystemimage.h", map.getValue("/filesystemimage.h"))
        assertEquals("/packfile.cpp", map.getValue("/packfile.cpp"))
    }

    @Test
    fun backslashPathsFoldToo() {
        // Windows-style separators count as full paths (stabs mixes both) — normalisation settles
        // them into one spelling before the fold ever sees them.
        val map = fold("foo.h", """C:\work\include\foo.h""")
        assertEquals("/C:/work/include/foo.h", map.getValue("/foo.h"))
    }

    @Test
    fun differentExtensionsAreDistinctFiles() {
        // A bare `.c` never folds onto a `.h` (different physical files sharing a stem).
        val map = fold("dspinfo.c", "/work/include/dspinfo/dspinfo.h")
        assertEquals("/dspinfo.c", map.getValue("/dspinfo.c"))
        assertEquals("/work/include/dspinfo/dspinfo.h", map.getValue("/work/include/dspinfo/dspinfo.h"))
    }
}
