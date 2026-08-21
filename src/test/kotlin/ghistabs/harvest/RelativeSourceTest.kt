package ghistabs.harvest

import ghistabs.parse.resolveAgainstDirectory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RelativeSourceTest {
    @Test
    fun parentSegmentsPopTheCompilationDirectory() {
        // bouniaf's `bits64.h`, the spelling that sent it to a made-up `interface/` root.
        assertEquals(
            "E:/work/cc/devtools/interface/host/bits/bits64.h",
            "../../../interface/host/bits/bits64.h"
                .resolveAgainstDirectory("E:/work/cc/devtools/devtools-bouniaf-7-0/vm/project/"),
        )
    }

    @Test
    fun bareAndAbsoluteSpellingsAreLeftAlone() {
        // A bare name is relative to the CU too, but resolving it splits headers staged into two
        // trees — see the doc on resolveAgainstDirectory.
        assertEquals("image.h", "image.h".resolveAgainstDirectory("/work/src/"))
        assertEquals("/usr/include/new", "/usr/include/new".resolveAgainstDirectory("/work/src/"))
    }

    @Test
    fun moreParentsThanDirectoryHasLeavesItUnchanged() {
        assertEquals("../../x.h", "../../x.h".resolveAgainstDirectory("/work/"))
    }

    @Test
    fun noCompilationDirectoryLeavesItUnchanged() {
        assertEquals("../x.h", "../x.h".resolveAgainstDirectory(null))
    }

    @Test
    fun backslashSpellingsResolveToo() {
        assertEquals("""C:\work\src/x.h""", """..\x.h""".resolveAgainstDirectory("""C:\work\src\sub\"""))
    }
}
