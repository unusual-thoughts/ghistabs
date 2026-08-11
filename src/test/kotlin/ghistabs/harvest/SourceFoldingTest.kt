package ghistabs.harvest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SourceFoldingTest {
    @Test
    fun bareFoldsOntoItsFullPath() {
        // The bare `header.h` and its single full-path spelling collapse onto the full one — the
        // render writes a tree, so the directory the stabs know is worth keeping.
        val map = foldSourcePaths(listOf("header.h", "/work/include/project/header.h"))
        assertEquals("/work/include/project/header.h", map.getValue("header.h"))
        assertEquals("/work/include/project/header.h", map.getValue("/work/include/project/header.h"))
    }

    @Test
    fun sameHeaderUnderDifferentBuildRootsFolds() {
        // One physical header (`bouniaf/image.h`) compiled in two build trees keeps its parent dir,
        // so every spelling folds onto one of them — the shallowest, being the least specific to a
        // single build root.
        val inputs = listOf("image.h", "/jenkins/build/project/image.h", "/work/project/image.h")
        val map = foldSourcePaths(inputs)
        for (i in inputs) assertEquals("/work/project/image.h", map.getValue(i))
    }

    @Test
    fun equalDepthRootsPickTheSameOneEveryTime() {
        // Two roots at the same depth are equally true; the tie-break is lexicographic so the choice
        // cannot drift with the order the spellings were harvested in.
        val inputs = listOf("/work/project/image.h", "/jenkins/project/image.h")
        val map = foldSourcePaths(inputs)
        val reversed = foldSourcePaths(inputs.reversed())
        for (i in inputs) assertEquals("/jenkins/project/image.h", map.getValue(i))
        assertEquals(map, reversed)
    }

    @Test
    fun distinctHeadersSharingBasenameDoNotMerge() {
        // Different parent dirs → genuinely distinct files; the bare name is ambiguous, nothing folds.
        val inputs = listOf("config.h", "/proj/moduleA/config.h", "/proj/moduleB/config.h")
        val map = foldSourcePaths(inputs)
        for (i in inputs) assertEquals(i, map.getValue(i))
    }

    @Test
    fun aBareNameWithNoFullSpellingStaysBare() {
        // Nothing better is known about it. `file.cpp` is a CU and never has one.
        val map = foldSourcePaths(listOf("filesystemimage.h", "file.cpp"))
        assertEquals("filesystemimage.h", map.getValue("filesystemimage.h"))
        assertEquals("file.cpp", map.getValue("file.cpp"))
    }

    @Test
    fun backslashPathsFoldToo() {
        // Windows-style separators count as full paths (stabs mixes both).
        val map = foldSourcePaths(listOf("foo.h", """C:\work\include\foo.h"""))
        assertEquals("""C:\work\include\foo.h""", map.getValue("foo.h"))
    }

    @Test
    fun differentExtensionsAreDistinctFiles() {
        // A bare `.c` never folds onto a `.h` (different physical files sharing a stem).
        val map = foldSourcePaths(listOf("file.c", "/work/include/project/header.h"))
        assertEquals("file.c", map.getValue("file.c"))
        assertEquals("/work/include/project/header.h", map.getValue("/work/include/project/header.h"))
    }
}
