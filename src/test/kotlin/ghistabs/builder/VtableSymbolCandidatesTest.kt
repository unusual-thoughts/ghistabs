package ghistabs.builder

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemangledFunction
import ghidra.app.util.demangler.DemangledNamespaceNode
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class VtableSymbolCandidatesTest {
    @Test
    fun testMangledZtvCandidatesSimpleName() {
        val candidates = VtableSymbolCandidates.mangledZtvCandidates("bouniaf")
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
    fun testMangledZtvCandidatesNestedName() {
        val candidates = VtableSymbolCandidates.mangledZtvCandidates("Foo::Bar")
        assertEquals("_ZTVN3Foo3BarE", candidates[0])
        assertEquals("__ZTVN3Foo3BarE", candidates[1])
    }

    @Test
    fun testItaniumMangledClassNameSimple() {
        assertEquals("10bouniaf", VtableSymbolCandidates.itaniumMangleClassName("bouniaf"))
    }

    @Test
    fun testItaniumMangledClassNameNested() {
        assertEquals("N3Foo3BarE", VtableSymbolCandidates.itaniumMangleClassName("Foo::Bar"))
    }

    @Test
    fun testItaniumMangledClassNameTripleNested() {
        assertEquals("N3Foo3Bar3BazE", VtableSymbolCandidates.itaniumMangleClassName("Foo::Bar::Baz"))
    }

    @Test
    fun testItaniumMangledClassNameTemplated() {
        assertEquals("vector<int>", VtableSymbolCandidates.itaniumMangleClassName("vector<int>"))
    }

    @Test
    fun testLooksLikeZtv() {
        assertTrue(VtableSymbolCandidates.looksLikeZtv("_ZTV10ThisStream"))
        assertTrue(VtableSymbolCandidates.looksLikeZtv("__ZTV10ThisStream"))
        assertTrue(VtableSymbolCandidates.looksLikeZtv("ZTVbare"))
        assertFalse(VtableSymbolCandidates.looksLikeZtv("XYZ_ZTV9ThisStream"))
        assertFalse(VtableSymbolCandidates.looksLikeZtv("_ZN3FooC1Ev"))
    }

    @Test
    fun testDemangledMatchesSimpleClass() {
        val obj = vtableObj("ThisStream")
        assertTrue(VtableSymbolCandidates.demangledMatchesClass(obj, "bouniaf"))
        assertFalse(VtableSymbolCandidates.demangledMatchesClass(obj, "OtherClass"))
    }

    @Test
    fun testDemangledMatchesNestedClass() {
        val obj = vtableObj("Foo", "Bar")
        assertTrue(VtableSymbolCandidates.demangledMatchesClass(obj, "Foo::Bar"))
        assertFalse(VtableSymbolCandidates.demangledMatchesClass(obj, "Foo"))
        assertFalse(VtableSymbolCandidates.demangledMatchesClass(obj, "Bar"))
    }

    @Test
    fun testDemangledMatchesRejectsNonVtable() {
        val func = DemangledFunction("_ZN3FooC1Ev", "Foo::Foo()", "Foo")
        func.namespace = DemangledNamespaceNode("_ZN3FooC1Ev", "Foo", "Foo")
        assertFalse(VtableSymbolCandidates.demangledMatchesClass(func, "Foo"))
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
