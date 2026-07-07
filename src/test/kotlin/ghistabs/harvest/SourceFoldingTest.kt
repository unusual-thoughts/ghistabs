package ghistabs.harvest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SourceFoldingTest {
    @Test
    fun bareFoldsUniqueFullPath() {
        // The bare `dspinfo.h` and its single full-path spelling collapse onto the bare (shorter) name.
        val map = foldSourcePaths(listOf("dspinfo.h", "/work/include/dspinfo/dspinfo.h"))
        assertEquals("dspinfo.h", map.getValue("dspinfo.h"))
        assertEquals("dspinfo.h", map.getValue("/work/include/dspinfo/dspinfo.h"))
    }

    @Test
    fun sameHeaderUnderDifferentBuildRootsFolds() {
        // One physical header (`xvimage/image.h`) compiled in two build trees keeps its parent dir,
        // so both full spellings fold onto the bare name.
        val inputs = listOf("image.h", "/jenkins/xvimage/image.h", "/work/xvimage/image.h")
        val map = foldSourcePaths(inputs)
        for (i in inputs) assertEquals("image.h", map.getValue(i))
    }

    @Test
    fun distinctHeadersSharingBasenameDoNotMerge() {
        // Different parent dirs → genuinely distinct files; the bare name is ambiguous, nothing folds.
        val inputs = listOf("config.h", "/proj/moduleA/config.h", "/proj/moduleB/config.h")
        val map = foldSourcePaths(inputs)
        for (i in inputs) assertEquals(i, map.getValue(i))
    }

    @Test
    fun fullPathWithoutBareSpellingStays() {
        // No bare spelling present → nothing to fold into; the full path renders under itself.
        val map = foldSourcePaths(listOf("/work/include/dspinfo/dspinfo.h", "packfile.cpp"))
        assertEquals("/work/include/dspinfo/dspinfo.h", map.getValue("/work/include/dspinfo/dspinfo.h"))
        assertEquals("packfile.cpp", map.getValue("packfile.cpp"))
    }

    @Test
    fun backslashPathsFoldToo() {
        // Windows-style separators count as full paths and fold onto the bare basename.
        val map = foldSourcePaths(listOf("foo.h", """C:\work\include\foo.h"""))
        assertEquals("foo.h", map.getValue("""C:\work\include\foo.h"""))
    }

    @Test
    fun differentExtensionsAreDistinctFiles() {
        // A bare `.c` never folds a `.h` (different physical files sharing a stem).
        val map = foldSourcePaths(listOf("dspinfo.c", "/work/include/dspinfo/dspinfo.h"))
        assertEquals("dspinfo.c", map.getValue("dspinfo.c"))
        assertEquals("/work/include/dspinfo/dspinfo.h", map.getValue("/work/include/dspinfo/dspinfo.h"))
    }
}
