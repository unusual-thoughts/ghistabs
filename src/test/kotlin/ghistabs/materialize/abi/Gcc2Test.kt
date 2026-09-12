package ghistabs.materialize.abi

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
        CxxAbi.of("_ZTV10ThisStream") mustBe Itanium
        CxxAbi.of("__vt_9TiXmlNode") mustBe Gcc2Thunks
        CxxAbi.of("_vt.9exception") mustBe Gcc2Plain
        CxxAbi.of("TiXmlNode::Parse") mustBe null
    }

    /**
     * A vtable spelling outranks a member spelling wherever the two disagree, and a binary with no
     * vtable at all is still settled by its members — a gcc 2.x C++ binary with no polymorphic class
     * would otherwise fall to Itanium and stop composing physnames.
     */
    @Test
    fun prevailingPrefersAVtableButSettlesForAMember() {
        val gcc2Members = sequenceOf("append__11TiXmlStringPCcUi", "_._9TiXmlNode")
        CxxAbi.prevailing(gcc2Members) mustBe Gcc2Thunks
        CxxAbi.prevailing(sequenceOf("_ZN9TiXmlNode5ParseEPKc")) mustBe Itanium
        CxxAbi.prevailing(gcc2Members + "_ZTV10ThisStream") mustBe Itanium
        CxxAbi.prevailing(sequenceOf("main", "memcpy", "_IO_stdout")) mustBe Itanium
    }

    /**
     * The two member detectors have to stay disjoint: one hit of the wrong one re-classifies a whole
     * binary. Measured over the fixtures — 32,574 real `_Z…` names match the gcc 2.x rule zero times,
     * and tinyxml's 215 gcc 2.x member names match the Itanium rule zero times — so these stand for
     * the shapes that came closest.
     */
    @Test
    fun theTwoMemberDetectorsDoNotOverlap() {
        Gcc2.mustNot { isProbablyMangled("_ZN9__gnu_cxx13new_allocatorE") }
        Gcc2.mustNot { isProbablyMangled("__ZNSt8__detail6_ScaleE") }
        Gcc2.mustNot { isProbablyMangled("__errno_location") }
        Gcc2.mustNot { isProbablyMangled("__vt_9TiXmlNode") }
        Gcc2.must { isProbablyMangled("Accept__C12TiXmlElementP12TiXmlVisitor") }
        Gcc2.must { isProbablyMangled("__as__11TiXmlStringPCc") }
        Gcc2.must { isProbablyMangled("_._9TiXmlNode") }
        Gcc2.must { isProbablyMangled("__Q217__class_type_info9base_info") }
        Itanium.mustNot { isProbablyMangled("__as__11TiXmlStringPCc") }
        Itanium.mustNot { isProbablyMangled("_._9TiXmlNode") }
    }

    /** Only gcc 2.x separates a secondary out; Itanium must not inherit a "no" from the default. */
    @Test
    fun onlyGcc2HasSecondariesToScreenOut() {
        Itanium.must { isPrimaryVtable("_ZTV10ThisStream") }
        Gcc2Plain.must { isPrimaryVtable("_vt.14CExposedStream") }
        Gcc2Plain.mustNot { isPrimaryVtable("_vt.14CExposedStream.11PRevertable") }
    }

    /**
     * With thunks an entry is a bare pointer; without, it is `{short delta; short index; void *pfn;}`
     * — 8 bytes on 32-bit with `pfn` in the second word, which is the whole reason the two need
     * telling apart before any slot is read.
     */
    @Test
    fun onlyTheNoThunkFormHasWideEntriesWithAnOffsetPfn() {
        Itanium.stride(4) mustBe 4L
        Gcc2Thunks.stride(4) mustBe 4L
        Gcc2Plain.stride(4) mustBe 8L

        Itanium.pfnOffset(4) mustBe 0L
        Gcc2Thunks.pfnOffset(4) mustBe 0L
        Gcc2Plain.pfnOffset(4) mustBe 4L
    }

    @Test
    fun onlyItaniumHasAnRttiHeaderToLocateTheAddressPointBy() {
        Itanium.hasRttiHeader mustBe true
        Gcc2Thunks.hasRttiHeader mustBe false
        Gcc2Plain.hasRttiHeader mustBe false
    }
}
