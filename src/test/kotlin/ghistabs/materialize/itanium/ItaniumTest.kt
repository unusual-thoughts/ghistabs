package ghistabs.materialize.itanium

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledFunction
import ghidra.app.util.demangler.DemangledNamespaceNode
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustNot
import org.junit.jupiter.api.Test

class ItaniumTest {
    @Test
    fun testZtvCandidatesSimpleName() {
        val candidates = Itanium.ztvCandidates("CLexStream")
        candidates mustBe listOf(
            "_ZTV10CLexStream",
            "__ZTV10CLexStream",
            $$"_vt$CLexStream$",
            "CLexStream::vtable",
        )
    }

    @Test
    fun testZtvCandidatesNestedName() {
        val candidates = Itanium.ztvCandidates("Foo::Bar")
        candidates[0] mustBe "_ZTVN3Foo3BarE"
        candidates[1] mustBe "__ZTVN3Foo3BarE"
    }

    @Test
    fun testMangleClassNameSimple() {
        Itanium.mangleClassName("CLexStream") mustBe "10CLexStream"
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
        Itanium.must { looksLikeZtv("_ZTV10CLexStream") }
        Itanium.must { looksLikeZtv("__ZTV10CLexStream") }
        Itanium.must { looksLikeZtv("ZTVbare") }
        Itanium.mustNot { looksLikeZtv("XYZ_ZTV9CLexStream") }
        Itanium.mustNot { looksLikeZtv("_ZN3FooC1Ev") }
    }

    @Test
    fun testDemangledMatchesSimpleClass() {
        val obj = vtableObj("CLexStream")
        Itanium.must { demangledMatchesClass(obj, "CLexStream") }
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
        func.namespace = DemangledNamespaceNode("_ZN3FooC1Ev", "Foo", "Foo")
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
        var node: DemangledNamespaceNode? = null
        for (p in parts) {
            val next = DemangledNamespaceNode("synthetic", p, p)
            next.namespace = node
            node = next
        }
        obj.namespace = node
        return obj
    }
}
