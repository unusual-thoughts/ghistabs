package ghistabs.index

import ghistabs.harvest.*
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** Spellings in, normalised paths out — the fold decides which spelling wins, the identity decides
 *  how it is written, and these assert the first against the second. */
private fun fold(vararg spellings: String) = foldSourcePaths(spellings.map(::sourceFileOf))
    .entries.associate { (raw, folded) -> raw.path to folded.path }

class SourceFoldingTest {
    @Test
    fun bareFoldsOntoItsFullPath() {
        // The bare `header.h` and its single full-path spelling collapse onto the full one — the
        // render writes a tree, so the directory the stabs know is worth keeping.
        val map = fold("header.h", "/work/include/project/header.h")
        map.getValue("/header.h") mustBe "/work/include/project/header.h"
        map.getValue("/work/include/project/header.h") mustBe "/work/include/project/header.h"
    }

    @Test
    fun sameHeaderUnderDifferentBuildRootsFolds() {
        // One physical header (`bouniaf/image.h`) compiled in two build trees keeps its parent dir,
        // so every spelling folds onto one of them — the shallowest, being the least specific to a
        // single build root. Equal depth here, so the lexicographic tie-break decides.
        val map = fold(
            "image.h",
            "/jenkins/bluesuite/result/include/project/image.h",
            "/work/devtools/result/include/project/image.h",
        )
        for (i in map.keys) map.getValue(i) mustBe "/jenkins/bluesuite/result/include/project/image.h"
    }

    @Test
    fun equalDepthRootsPickTheSameOneEveryTime() {
        // Two roots at the same depth are equally true; the tie-break is lexicographic so the choice
        // cannot drift with the order the spellings were harvested in.
        val map = fold("/work/include/project/image.h", "/jenkins/include/project/image.h")
        val reversed = fold("/jenkins/include/project/image.h", "/work/include/project/image.h")
        for (i in map.keys) map.getValue(i) mustBe "/jenkins/include/project/image.h"
        reversed mustBe map
    }

    @Test
    fun headersSharingOnlyACommonParentNameDoNotMerge() {
        // mingw's `stdarg.h` and gcc's own both sit in an `include/`, which is why one directory of
        // agreement is not enough to call two paths the same file.
        val map = fold("c:/mingw/include/stdarg.h", "c:/mingw/lib/gcc-lib/mingw32/3.2.3/include/stdarg.h")
        for (i in map.keys) map.getValue(i) mustBe i
    }

    @Test
    fun distinctHeadersSharingBasenameDoNotMerge() {
        // Different parent dirs → genuinely distinct files; the bare name is ambiguous, nothing folds.
        val map = fold("config.h", "/proj/moduleA/config.h", "/proj/moduleB/config.h")
        for (i in map.keys) map.getValue(i) mustBe i
    }

    @Test
    fun aBareNameWithNoFullSpellingStaysBare() {
        // Nothing better is known about it. A CU never has one.
        val map = fold("filesystemimage.h", "main.cpp")
        map.getValue("/filesystemimage.h") mustBe "/filesystemimage.h"
        map.getValue("/main.cpp") mustBe "/main.cpp"
    }

    @Test
    fun backslashPathsFoldToo() {
        // Windows-style separators count as full paths (stabs mixes both) — normalisation settles
        // them into one spelling before the fold ever sees them.
        val map = fold("foo.h", """C:\work\include\foo.h""")
        map.getValue("/foo.h") mustBe "/C:/work/include/foo.h"
    }

    @Test
    fun differentExtensionsAreDistinctFiles() {
        // A bare `.c` never folds onto a `.h` (different physical files sharing a stem).
        val map = fold("file.c", "/work/include/project/header.h")
        map.getValue("/file.c") mustBe "/file.c"
        map.getValue("/work/include/project/header.h") mustBe "/work/include/project/header.h"
    }
}
