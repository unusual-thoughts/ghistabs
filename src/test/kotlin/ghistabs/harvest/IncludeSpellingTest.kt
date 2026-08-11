package ghistabs.harvest

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class IncludeSpellingTest {
    @Test
    fun bareAndRelativeSpellingsAreQuoted() {
        // cpp only searches the including file's own directory for `"…"`, so these are certain.
        assertEquals(""""filesystemimage.h"""", includeSpelling("filesystemimage.h"))
        assertEquals(""""bits64.h"""", includeSpelling("../../../interface/host/bits/bits64.h"))
    }

    @Test
    fun libstdcxxHeadersAreAngledBelowTheirRoot() {
        assertEquals("<vector>", includeSpelling("c:/mingw/include/c++/3.2.3/vector"))
        assertEquals("<bits/stl_alloc.h>", includeSpelling("c:/mingw/include/c++/3.2.3/bits/stl_alloc.h"))
        assertEquals("<new>", includeSpelling("/usr/include/c++/12/new"))
    }

    @Test
    fun theTargetConfigDirectoryIsASearchRootToo() {
        // `c++/3.2.3/mingw32/` is where libstdc++ puts the target's own copies; it is on the search
        // path, so the spelling is <bits/atomicity.h>, not <mingw32/bits/atomicity.h>.
        assertEquals(
            "<bits/atomicity.h>",
            includeSpelling("c:/mingw/include/c++/3.2.3/mingw32/bits/atomicity.h"),
        )
    }

    @Test
    fun cHeadersUnderAToolchainRootAreAngled() {
        assertEquals("<string.h>", includeSpelling("c:/mingw/include/string.h"))
        assertEquals("<stddef.h>", includeSpelling("c:/mingw/lib/gcc-lib/mingw32/3.2.3/include/stddef.h"))
        // Not a c++ root, so `sys` is part of the spelling rather than a target directory.
        assertEquals("<sys/types.h>", includeSpelling("/usr/include/sys/types.h"))
    }

    @Test
    fun projectHeadersStayQuotedAndKeepTheirSubdirectory() {
        // Reached by -I, which the stabs cannot tell from a system root — so no `<…>` is asserted.
        assertEquals(
            """"imageutil/appimage.h"""",
            includeSpelling("E:/work/cc/devtools/devtools-bluelab-7-0/result/include/imageutil/appimage.h"),
        )
        assertEquals(
            """"bits64.h"""",
            includeSpelling("C:/Jenkins/workspace/BlueSuite/bc/bluesuite_2_6/interface/host/bits/bits64.h"),
        )
    }
}
