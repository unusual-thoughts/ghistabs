package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledFunction
import ghidra.app.util.demangler.DemangledType
import ghistabs.materialize.abi.CxxAbi
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustNot
import org.junit.jupiter.api.Test

class ItaniumTest {
    @Test
    fun testZtvCandidatesSimpleName() {
        Itanium.vtableCandidates("ThisStream") mustBe listOf(
            "_ZTV10ThisStream",
            "__ZTV10ThisStream",
            "ThisStream::vtable",
        )
    }

    @Test
    fun testEveryAbiContributesItsOwnCandidates() {
        // The gcc 2.x forms are length-prefixed like Itanium's and carry no trailing marker: the
        // libstdc++-2.8.1 binaries spell them `_vt.9exception`, and a second marker there is the
        // separator before a base (`_vt.14CExposedStream.11PRevertable` = that base's own vtable).
        CxxAbi.vtableCandidates("ThisStream") mustBe listOf(
            "_ZTV10ThisStream",
            "__ZTV10ThisStream",
            "ThisStream::vtable",
            $$"_vt$10ThisStream",
            "_vt.10ThisStream",
            "__vt_10ThisStream",
        )
    }

    @Test
    fun testZtvCandidatesNestedName() {
        val candidates = Itanium.vtableCandidates("Foo::Bar")
        candidates[0] mustBe "_ZTVN3Foo3BarE"
        candidates[1] mustBe "__ZTVN3Foo3BarE"
    }

    @Test
    fun testMangleClassNameSimple() {
        Itanium.mangleClassName("ThisStream") mustBe "10ThisStream"
    }

    @Test
    fun testMangleClassNameNested() {
        Itanium.mangleClassName("Foo::Bar") mustBe "N3Foo3BarE"
    }

    @Test
    fun testMangleClassNameTripleNested() {
        Itanium.mangleClassName("Foo::Bar::Baz") mustBe "N3Foo3Bar3BazE"
    }

    @Test
    fun testMangleClassNameTemplated() {
        Itanium.mangleClassName("vector<int>") mustBe "vector<int>"
    }

    @Test
    fun testLooksLikeZtv() {
        Itanium.must { Itanium.looksLikeVtable("_ZTV10ThisStream") }
        Itanium.must { Itanium.looksLikeVtable("__ZTV10ThisStream") }
        Itanium.mustNot { Itanium.looksLikeVtable("ZTVbare") }
        Itanium.mustNot { Itanium.looksLikeVtable("XYZ_ZTV9ThisStream") }
        Itanium.mustNot { Itanium.looksLikeVtable("_ZN3FooC1Ev") }
    }

    @Test
    fun testDemangledMatchesSimpleClass() {
        val obj = vtableObj("ThisStream")
        Itanium.must { demangledMatchesClass(obj, "ThisStream") }
        Itanium.mustNot { demangledMatchesClass(obj, "OtherClass") }
    }

    @Test
    fun testDemangledMatchesNestedClass() {
        val obj = vtableObj("Foo", "Bar")
        Itanium.must { demangledMatchesClass(obj, "Foo::Bar") }
        Itanium.mustNot { demangledMatchesClass(obj, "Foo") }
        Itanium.mustNot { demangledMatchesClass(obj, "Bar") }
    }

    @Test
    fun testDemangledMatchesRejectsNonVtable() {
        val func = DemangledFunction("_ZN3FooC1Ev", "Foo::Foo()", "Foo")
        func.namespace = DemangledType("_ZN3FooC1Ev", "Foo", "Foo")
        Itanium.mustNot { demangledMatchesClass(func, "Foo") }
    }

    /**
     * Build a synthetic `DemangledAddressTable("vtable", parts...)` shaped
     * like Ghidra's GnuDemangler output for `_ZTV…`. The namespace chain
     * is linked leaf-pointing-at-parent so iteration via `obj.namespace`
     * walks deepest-first.
     */
    private fun vtableObj(vararg parts: String): DemangledAddressTable {
        val obj = DemangledAddressTable("synthetic", "synthetic-vtable", "vtable", false)
        var node: DemangledType? = null
        for (p in parts) {
            val next = DemangledType("synthetic", p, p)
            next.namespace = node
            node = next
        }
        obj.namespace = node
        return obj
    }
}
