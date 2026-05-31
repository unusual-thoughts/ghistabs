package ghistabs.builder

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class VtableSymbolCandidatesTest {
    @Test
    fun testMangledZtvCandidatesSimpleName() {
        val candidates = VtableSymbolCandidates.mangledZtvCandidates("CLexStream")
        assertEquals(
            listOf(
                "_ZTV10CLexStream",
                "__ZTV10CLexStream",
                $$"_vt$CLexStream$",
                "CLexStream::vtable",
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
        val result = VtableSymbolCandidates.itaniumMangleClassName("CLexStream")
        assertEquals("10CLexStream", result)
    }

    @Test
    fun testItaniumMangledClassNameNested() {
        val result = VtableSymbolCandidates.itaniumMangleClassName("Foo::Bar")
        assertEquals("N3Foo3BarE", result)
    }

    @Test
    fun testItaniumMangledClassNameTripleNested() {
        val result = VtableSymbolCandidates.itaniumMangleClassName("Foo::Bar::Baz")
        assertEquals("N3Foo3Bar3BazE", result)
    }

    @Test
    fun testItaniumMangledClassNameTemplated() {
        val result = VtableSymbolCandidates.itaniumMangleClassName("vector<int>")
        assertEquals("vector<int>", result)
    }

    @Test
    fun testItaniumDecodesToClassMatches() {
        assertTrue(
            VtableSymbolCandidates.itaniumDecodesToClass("_ZTV10CLexStream", "CLexStream"),
            "Should decode _ZTV10CLexStream to CLexStream",
        )
    }

    @Test
    fun testItaniumDecodesToClassMatchesCygwinVariant() {
        assertTrue(
            VtableSymbolCandidates.itaniumDecodesToClass("__ZTV10CLexStream", "CLexStream"),
            "Should decode __ZTV10CLexStream (Cygwin variant) to CLexStream",
        )
    }

    @Test
    fun testItaniumDecodesToClassMatchesNested() {
        assertTrue(
            VtableSymbolCandidates.itaniumDecodesToClass("_ZTVN3Foo3BarE", "Foo::Bar"),
            "Should decode _ZTVN3Foo3BarE to Foo::Bar",
        )
    }

    @Test
    fun testItaniumDecodesToClassNoMatch() {
        assertFalse(
            VtableSymbolCandidates.itaniumDecodesToClass("XYZ_ZTV9CLexStream", "CLexStream"),
            "Should not match if prefix is not _ZTV or __ZTV",
        )
    }

    @Test
    fun testItaniumDecodesToClassWrongClass() {
        assertFalse(
            VtableSymbolCandidates.itaniumDecodesToClass("_ZTV3Foo", "Bar"),
            "Should not match if mangled form doesn't match class",
        )
    }
}
