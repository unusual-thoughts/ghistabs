package ghistabs.harvest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RelativeSourceTest {
    @Test
    fun parentSegmentsPopTheCompilationDirectory() {
        // bouniaf's `bits64.h`, the spelling that sent it to a made-up `interface/` root.
        assertEquals(
            "E:/work/cc/devtools/interface/host/bits/bits64.h",
            resolveAgainstDirectory(
                "../../../interface/host/bits/bits64.h",
                "E:/work/cc/devtools/devtools-bouniaf-7-0/vm/project/",
            ),
        )
    }

    @Test
    fun bareAndAbsoluteSpellingsAreLeftAlone() {
        // A bare name is relative to the CU too, but resolving it splits headers staged into two
        // trees — see the doc on resolveAgainstDirectory.
        assertEquals("image.h", resolveAgainstDirectory("image.h", "/work/src/"))
        assertEquals("/usr/include/new", resolveAgainstDirectory("/usr/include/new", "/work/src/"))
    }

    @Test
    fun moreParentsThanDirectoryHasLeavesItUnchanged() {
        assertEquals("../../x.h", resolveAgainstDirectory("../../x.h", "/work/"))
    }

    @Test
    fun noCompilationDirectoryLeavesItUnchanged() {
        assertEquals("../x.h", resolveAgainstDirectory("../x.h", null))
    }

    @Test
    fun backslashSpellingsResolveToo() {
        assertEquals("""C:\work\src/x.h""", resolveAgainstDirectory("""..\x.h""", """C:\work\src\sub\"""))
    }
}
