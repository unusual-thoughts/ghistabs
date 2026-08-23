package ghistabs.harvest

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** The spelling is read off the identity, so the identity is what the fixtures are written as. */
private fun includeSpellingOf(spelling: String) = includeSpelling(sourceFileOf(spelling))

class IncludeSpellingTest {
    @Test
    fun bareAndRelativeSpellingsAreQuoted() {
        // cpp only searches the including file's own directory for `"…"`, so these are certain.
        includeSpellingOf("filesystemimage.h") mustBe """"filesystemimage.h""""
        includeSpellingOf("../../../interface/host/bits/bits64.h") mustBe """"bits64.h""""
    }

    @Test
    fun libstdcxxHeadersAreAngledBelowTheirRoot() {
        includeSpellingOf("c:/mingw/include/c++/3.2.3/vector") mustBe "<vector>"
        includeSpellingOf("c:/mingw/include/c++/3.2.3/bits/stl_alloc.h") mustBe "<bits/stl_alloc.h>"
        includeSpellingOf("/usr/include/c++/12/new") mustBe "<new>"
    }

    @Test
    fun theTargetConfigDirectoryIsASearchRootToo() {
        // `c++/3.2.3/mingw32/` is where libstdc++ puts the target's own copies; it is on the search
        // path, so the spelling is <bits/atomicity.h>, not <mingw32/bits/atomicity.h>.
        includeSpellingOf("c:/mingw/include/c++/3.2.3/mingw32/bits/atomicity.h") mustBe "<bits/atomicity.h>"
    }

    @Test
    fun cHeadersUnderAToolchainRootAreAngled() {
        includeSpellingOf("c:/mingw/include/string.h") mustBe "<string.h>"
        includeSpellingOf("c:/mingw/lib/gcc-lib/mingw32/3.2.3/include/stddef.h") mustBe "<stddef.h>"
        // Not a c++ root, so `sys` is part of the spelling rather than a target directory.
        includeSpellingOf("/usr/include/sys/types.h") mustBe "<sys/types.h>"
    }

    @Test
    fun projectHeadersStayQuotedAndKeepTheirSubdirectory() {
        // Reached by -I, which the stabs cannot tell from a system root — so no `<…>` is asserted.
        includeSpellingOf("E:/work/cc/devtools/devtools-bouniaf-7-0/result/include/imageutil/appimage.h") mustBe
            """"imageutil/appimage.h""""
        includeSpellingOf("C:/Jenkins/workspace/project/bc/bluesuite_2_6/interface/host/bits/bits64.h") mustBe
            """"bits64.h""""
    }
}
