package ghistabs.materialize.itanium

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledFunction
import ghidra.app.util.demangler.DemangledNamespaceNode
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ItaniumTest {
    @Test
    fun testZtvCandidatesSimpleName() {
        val candidates = Itanium.ztvCandidates("ThisStream")
        assertEquals(
            listOf(
                "_ZTV10ThisStream",
                "__ZTV10ThisStream",
                $$"_vt$ThisStream$",
                "ThisStream::vtable",
            ),
            candidates,
        )
    }

    @Test
    fun testZtvCandidatesNestedName() {
        val candidates = Itanium.ztvCandidates("Foo::Bar")
        assertEquals("_ZTVN3Foo3BarE", candidates[0])
        assertEquals("__ZTVN3Foo3BarE", candidates[1])
    }

    @Test
    fun testMangleClassNameSimple() {
        assertEquals("10bouniaf", Itanium.mangleClassName("bouniaf"))
    }

    @Test
    fun testMangleClassNameNested() {
        assertEquals("N3Foo3BarE", Itanium.mangleClassName("Foo::Bar"))
    }

    @Test
    fun testMangleClassNameTripleNested() {
        assertEquals("N3Foo3Bar3BazE", Itanium.mangleClassName("Foo::Bar::Baz"))
    }

    @Test
    fun testMangleClassNameTemplated() {
        assertEquals("vector<int>", Itanium.mangleClassName("vector<int>"))
    }

    @Test
    fun testLooksLikeZtv() {
        assertTrue(Itanium.looksLikeZtv("_ZTV10ThisStream"))
        assertTrue(Itanium.looksLikeZtv("__ZTV10ThisStream"))
        assertTrue(Itanium.looksLikeZtv("ZTVbare"))
        assertFalse(Itanium.looksLikeZtv("XYZ_ZTV9ThisStream"))
        assertFalse(Itanium.looksLikeZtv("_ZN3FooC1Ev"))
    }

    @Test
    fun testDemangledMatchesSimpleClass() {
        val obj = vtableObj("ThisStream")
        assertTrue(Itanium.demangledMatchesClass(obj, "bouniaf"))
        assertFalse(Itanium.demangledMatchesClass(obj, "OtherClass"))
    }

    @Test
    fun testDemangledMatchesNestedClass() {
        val obj = vtableObj("Foo", "Bar")
        assertTrue(Itanium.demangledMatchesClass(obj, "Foo::Bar"))
        assertFalse(Itanium.demangledMatchesClass(obj, "Foo"))
        assertFalse(Itanium.demangledMatchesClass(obj, "Bar"))
    }

    @Test
    fun testDemangledMatchesRejectsNonVtable() {
        val func = DemangledFunction("_ZN3FooC1Ev", "Foo::Foo()", "Foo")
        func.namespace = DemangledNamespaceNode("_ZN3FooC1Ev", "Foo", "Foo")
        assertFalse(Itanium.demangledMatchesClass(func, "Foo"))
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
