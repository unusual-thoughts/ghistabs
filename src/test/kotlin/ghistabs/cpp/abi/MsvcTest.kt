package ghistabs.cpp.abi

import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class MsvcTest {
    private val space = GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0)

    // A type descriptor's address, one per class name.
    private fun td(name: String) = space.getAddress(name.hashCode().toLong() and 0xffff)

    private fun entry(type: String, contained: Int = 0, isVirtual: Boolean = false) =
        BaseEntry(td(type), contained, isVirtual, isPublic = true)

    @Test
    fun `direct bases step over each base's own`() {
        // class D : B, S, with B : A
        val array = listOf(entry("D", 3), entry("B", 1), entry("A"), entry("S"))
        assertEquals(listOf("B", "S").map(::td), directBases(array).map { it.typeDescriptor })
    }

    @Test
    fun `a virtual base hoisted out from under its base is not direct`() {
        // class D : B, with B : virtual V, which MSVC lists both under B and after it
        val array = listOf(entry("D", 2), entry("B", 1), entry("V", isVirtual = true), entry("V", isVirtual = true))
        assertEquals(listOf(td("B")), directBases(array).map { it.typeDescriptor })
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

    @Test
    fun `msvc members vote, and a few msvc imports don't outvote gcc's own members`() {
        assertEquals(Msvc, CxxAbi.prevailing(sequenceOf("??0Image@@QAE@XZ", "?read@Image@@UAE_NXZ", "main")))
        val imports = sequenceOf("??2@YAPAXI@Z", "??3@YAXPAX@Z")
        assertEquals(Itanium, CxxAbi.prevailing(imports + "_ZN5Image4readEv" + "_ZN5ImageC1Ev" + "_ZN5ImageD1Ev"))
    }
}
