package ghistabs.cpp.abi

import ghistabs.cpp.abi.StructorKind.CONSTRUCTOR
import ghistabs.cpp.abi.StructorKind.DELETING_DESTRUCTOR
import ghistabs.cpp.abi.StructorKind.DESTRUCTOR
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Test

class StructorsTest {
    // class B : A; class X
    private val ancestors = mapOf("A" to setOf(), "B" to setOf("A"), "X" to setOf<String>())

    private fun stores(vararg classes: String, returnsThis: Boolean = false) = VptrStores(classes.toSet(), returnsThis)

    private fun structors(
        storers: Map<String, VptrStores<String>>,
        holders: Map<String, Set<String>>,
        calls: Map<String, Set<String>> = emptyMap(),
        constructorsReturnThis: Boolean = true,
    ) = structors(storers, holders, { calls[it].orEmpty() }, ancestors::getValue, constructorsReturnThis)

    @Test
    fun `a function storing a base's vptr and then its own builds the derived class`() {
        storedClass(setOf("A", "B"), ancestors::getValue) mustBe "B"
        storedClass(setOf("A", "X"), ancestors::getValue).mustBeNull()
    }

    @Test
    fun `constructors return this, destructors don't, and the slot that calls one deletes`() {
        val storers = mapOf("ctor" to stores("A", returnsThis = true), "dtor" to stores("A"))
        val found = structors(storers, mapOf("slot" to setOf("A", "B")), mapOf("slot" to setOf("dtor", "free")))
        found mustBe mapOf(
            "ctor" to ("A" to CONSTRUCTOR),
            "dtor" to ("A" to DESTRUCTOR),
            "slot" to ("A" to DELETING_DESTRUCTOR),
        )
    }

    @Test
    fun `a slot storing the vptr itself has the destructor inlined`() {
        val storers = mapOf(
            "slot" to stores("A", "B", returnsThis = true),
            "ctor" to stores("A", "B", returnsThis = true),
        )
        structors(storers, mapOf("slot" to setOf("B"))) mustBe mapOf(
            "slot" to ("B" to DELETING_DESTRUCTOR),
            "ctor" to ("B" to CONSTRUCTOR),
        )
    }

    @Test
    fun `a derived class's destructor with nothing to do leaves only its base's vptr store`() {
        // B's deleting destructor, in B's table alone, calls a destructor that stores A's vptr
        val found = structors(mapOf("dtor" to stores("A")), mapOf("slot" to setOf("B")), mapOf("slot" to setOf("dtor")))
        found mustBe mapOf("slot" to ("B" to DELETING_DESTRUCTOR), "dtor" to ("A" to DESTRUCTOR))
    }

    @Test
    fun `a slot calling a constructor, as a clone does, deletes nothing`() {
        val storers = mapOf("ctor" to stores("A", returnsThis = true))
        structors(storers, mapOf("clone" to setOf("A")), mapOf("clone" to setOf("ctor")))["clone"].mustBeNull()
    }

    @Test
    fun `without constructors returning this, only a deleting destructor's callee is told`() {
        val storers = mapOf("ctor" to stores("A"), "dtor" to stores("A"))
        val found = structors(storers, mapOf("slot" to setOf("A")), mapOf("slot" to setOf("dtor")), false)
        found mustBe mapOf("slot" to ("A" to DELETING_DESTRUCTOR), "dtor" to ("A" to DESTRUCTOR))
    }
}
