package ghistabs.harvest

import ghistabs.parse.resolveAgainstDirectory
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class RelativeSourceTest {
    @Test
    fun parentSegmentsPopTheCompilationDirectory() {
        // A `../../../` spelling of the kind that sent a header to a made-up `interface/` root.
        "../../../interface/host/bits/bits64.h"
            .resolveAgainstDirectory("E:/work/cc/devtools/toolchain/vm/tool/") mustBe
            "E:/work/cc/devtools/interface/host/bits/bits64.h"
    }

    @Test
    fun bareAndAbsoluteSpellingsAreLeftAlone() {
        // A bare name is relative to the CU too, but resolving it splits headers staged into two
        // trees — see the doc on resolveAgainstDirectory.
        "image.h".resolveAgainstDirectory("/work/src/") mustBe "image.h"
        "/usr/include/new".resolveAgainstDirectory("/work/src/") mustBe "/usr/include/new"
    }

    @Test
    fun moreParentsThanDirectoryHasLeavesItUnchanged() {
        "../../x.h".resolveAgainstDirectory("/work/") mustBe "../../x.h"
    }

    @Test
    fun noCompilationDirectoryLeavesItUnchanged() {
        "../x.h".resolveAgainstDirectory(null) mustBe "../x.h"
    }

    @Test
    fun backslashSpellingsResolveToo() {
        """..\x.h""".resolveAgainstDirectory("""C:\work\src\sub\""") mustBe """C:\work\src/x.h"""
    }
}
