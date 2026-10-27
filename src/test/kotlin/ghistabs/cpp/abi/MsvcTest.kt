package ghistabs.cpp.abi

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class MsvcTest {
    private fun entry(type: String, contained: Int = 0, isVirtual: Boolean = false) =
        BaseEntry(type, contained, isVirtual, isPublic = true)

    @Test
    fun `direct bases step over each base's own`() {
        // class D : B, S, with B : A
        val array = listOf(entry("D", 3), entry("B", 1), entry("A"), entry("S"))
        assertEquals(listOf("B", "S"), directBases(array).map { it.type })
    }

    @Test
    fun `a virtual base hoisted out from under its base is not direct`() {
        // class D : B, with B : virtual V, which MSVC lists both under B and after it
        val array = listOf(entry("D", 2), entry("B", 1), entry("V", isVirtual = true), entry("V", isVirtual = true))
        assertEquals(listOf("B"), directBases(array).map { it.type })
    }

    private val bases = mapOf(
        "A" to setOf(),
        "B" to setOf("A"),
        "C" to setOf("A"),
        "D" to setOf("B", "A"),
        "X" to setOf(),
        "Abstract" to setOf(),
        "P" to setOf("Abstract"),
        "Q" to setOf("Abstract"),
    )

    private fun owners(holders: Map<String, Set<String>>, withTable: Set<String> = bases.keys - "Abstract") =
        virtualOwners(holders, { bases.getValue(it) }, { it in withTable })

    @Test
    fun `an inherited function belongs to the class that introduced it`() {
        assertEquals("A", owners(mapOf("f" to setOf("A", "B", "C", "D")))["f"])
        assertEquals("B", owners(mapOf("f" to setOf("B", "D")))["f"])
        assertEquals("D", owners(mapOf("f" to setOf("D")))["f"])
    }

    @Test
    fun `siblings' function belongs to a common base with no vftable`() {
        assertEquals("Abstract", owners(mapOf("f" to setOf("P", "Q")))["f"])
    }

    @Test
    fun `folded overrides belong to no one`() {
        // B and C both override A's slot with code the linker folded into one body
        assertNull(owners(mapOf("f" to setOf("B", "C")))["f"])
        // unrelated classes share nothing but the body
        assertNull(owners(mapOf("f" to setOf("A", "X")))["f"])
    }

    @Test
    fun `msvc mangles a nested class innermost first`() {
        assertEquals("Foo@b@a@@", Msvc.mangleClassName("a::b::Foo"))
        assertEquals(listOf("??_7Foo@@6B@", "Foo::vftable"), Msvc.vtableCandidates("Foo"))
    }
}
