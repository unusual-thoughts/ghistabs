package ghistabs.materialize.itanium

import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustNot
import org.junit.jupiter.api.Test

/**
 * Names and geometry are both pure, and both were established from evidence rather than inference:
 * the spellings from `cv_mscom_elf_i386_gcc281` and `tinyxml_aout_gcc295.o`, the strides from gcc
 * 2.95.3 `cp/decl.c` + `cp/class.c:skip_rtti_stuff`.
 */
class Gcc2Test {
    @Test
    fun recognisesBothMarkersAndTheThunkSpelling() {
        Gcc2.must { looksLikeVtable("_vt.9exception") }
        Gcc2.must { looksLikeVtable($$"_vt$9exception") }
        Gcc2.must { looksLikeVtable("__vt_9TiXmlNode") }
        Gcc2.mustNot { looksLikeVtable("_ZTV10ThisStream") }
        // `_vt` with no marker is not the form, and neither is a name that merely contains it.
        Gcc2.mustNot { looksLikeVtable("_vt9exception") }
        Gcc2.mustNot { looksLikeVtable("x_vt.9exception") }
    }

    @Test
    fun onlyTheThunkSpellingIsThunked() {
        Gcc2.must { looksLikeThunkVtable("__vt_9TiXmlNode") }
        Gcc2.mustNot { looksLikeThunkVtable("_vt.9TiXmlNode") }
    }

    /**
     * The distinction the sweep turns on: a second marker names a *base's* secondary table inside
     * the first class, which is a different object from that class's own and from the base's own.
     */
    @Test
    fun aSecondMarkerMeansASecondaryTableNotANestedClass() {
        Gcc2.must { looksLikePrimaryVtable("_vt.14CExposedStream") }
        Gcc2.must { looksLikePrimaryVtable("_vt.11PRevertable") }
        Gcc2.mustNot { looksLikePrimaryVtable("_vt.14CExposedStream.11PRevertable") }
        // A genuinely nested class takes the `Q` form, so it stays a primary.
        Gcc2.must { looksLikePrimaryVtable("_vt.Q2_6Outer5Inner") }
    }

    @Test
    fun abiFollowsTheSpelling() {
        VtableAbi.of("_ZTV10ThisStream") mustBe VtableAbi.ITANIUM
        VtableAbi.of("__vt_9TiXmlNode") mustBe VtableAbi.GCC2_THUNKS
        VtableAbi.of("_vt.9exception") mustBe VtableAbi.GCC2_PLAIN
    }

    /**
     * With thunks an entry is a bare pointer; without, it is `{short delta; short index; void *pfn;}`
     * — 8 bytes on 32-bit with `pfn` in the second word, which is the whole reason the two need
     * telling apart before any slot is read.
     */
    @Test
    fun onlyTheNoThunkFormHasWideEntriesWithAnOffsetPfn() {
        VtableAbi.ITANIUM.stride(4) mustBe 4L
        VtableAbi.GCC2_THUNKS.stride(4) mustBe 4L
        VtableAbi.GCC2_PLAIN.stride(4) mustBe 8L

        VtableAbi.ITANIUM.pfnOffset(4) mustBe 0L
        VtableAbi.GCC2_THUNKS.pfnOffset(4) mustBe 0L
        VtableAbi.GCC2_PLAIN.pfnOffset(4) mustBe 4L
    }

    @Test
    fun onlyItaniumHasAnRttiHeaderToLocateTheAddressPointBy() {
        VtableAbi.ITANIUM.hasRttiHeader mustBe true
        VtableAbi.GCC2_THUNKS.hasRttiHeader mustBe false
        VtableAbi.GCC2_PLAIN.hasRttiHeader mustBe false
    }
}
