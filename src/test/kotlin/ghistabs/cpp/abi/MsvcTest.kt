package ghistabs.cpp.abi

import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghistabs.cpp.Access
import ghistabs.cpp.abi.msvc.BaseEntry
import ghistabs.cpp.abi.msvc.directBases
import ghistabs.cpp.abi.msvc.virtualOwners
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Test

class MsvcTest {
    private val space = GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0)

    // A type descriptor's address, one per class name.
    private fun td(name: String) = space.getAddress(name.hashCode().toLong() and 0xffff)

    private fun entry(type: String, contained: Int = 0, isVirtual: Boolean = false) =
        BaseEntry(td(type), contained, isVirtual, Access.PUBLIC)

    @Test
    fun `direct bases step over each base's own`() {
        // class D : B, S, with B : A
        val array = listOf(entry("D", 3), entry("B", 1), entry("A"), entry("S"))
        directBases(array).map { it.descriptor } mustBe listOf("B", "S").map(::td)
    }

    @Test
    fun `a virtual base hoisted out from under its base is not direct`() {
        // class D : B, with B : virtual V, which MSVC lists both under B and after it
        val array = listOf(entry("D", 2), entry("B", 1), entry("V", isVirtual = true), entry("V", isVirtual = true))
        directBases(array).map { it.descriptor } mustBe listOf(td("B"))
    }

    @Test
    fun `a base is virtual by its descriptor's flag, not by sitting inside a virtual base`() {
        // class D : virtual B, with B : A: A has a pDisp too, but only B is declared virtual
        BaseEntry(td("B"), 1, 0x40 or Msvc.BCD_VBOFCONTOBJ).isVirtual mustBe true
        BaseEntry(td("A"), 0, 0x40).isVirtual mustBe false
        BaseEntry(td("P"), 0, 0x40 or 0x4).access mustBe Access.PRIVATE
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
        owners(mapOf("f" to setOf("A", "B", "C", "D")))["f"] mustBe "A"
        owners(mapOf("f" to setOf("B", "D")))["f"] mustBe "B"
        owners(mapOf("f" to setOf("D")))["f"] mustBe "D"
    }

    @Test
    fun `siblings' function belongs to a common base with no vftable`() {
        owners(mapOf("f" to setOf("P", "Q")))["f"] mustBe "Abstract"
    }

    @Test
    fun `folded overrides belong to no one`() {
        // B and C both override A's slot with code the linker folded into one body
        owners(mapOf("f" to setOf("B", "C")))["f"].mustBeNull()
        // unrelated classes share nothing but the body
        owners(mapOf("f" to setOf("A", "X")))["f"].mustBeNull()
    }

    @Test
    fun `msvc mangles a nested class innermost first`() {
        Msvc.mangleClassName("a::b::Foo") mustBe "Foo@b@a@@"
        Msvc.vtableCandidates("Foo") mustBe listOf("??_7Foo@@6B@", "Foo::vftable")
    }

    @Test
    fun `msvc members vote, and a few msvc imports don't outvote gcc's own members`() {
        CxxAbi.prevailing(sequenceOf("??0Image@@QAE@XZ", "?read@Image@@UAE_NXZ", "main")) mustBe Msvc
        val imports = sequenceOf("??2@YAPAXI@Z", "??3@YAXPAX@Z")
        CxxAbi.prevailing(imports + "_ZN5Image4readEv" + "_ZN5ImageC1Ev" + "_ZN5ImageD1Ev") mustBe Itanium
    }
}
