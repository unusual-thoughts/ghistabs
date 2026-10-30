package ghistabs.cpp.recover

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.TestClass
import ghistabs.cpp.abi.StructorConvention
import ghistabs.cpp.abi.StructorRole.CONSTRUCTOR
import ghistabs.cpp.abi.StructorRole.DELETING_DESTRUCTOR
import ghistabs.cpp.abi.StructorRole.DESTRUCTOR
import ghistabs.cpp.abi.itanium.Itanium
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("integration")
class StructorsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val functions = mutableMapOf<String, Function>()

    // class B : A; class X
    private val a = TestClass("A")
    private val b = TestClass("B", a)
    private val x = TestClass("X")

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("structors", ProgramBuilder._X86)
        builder.createMemory(".text", "0x401000", 0x1000)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun fn(name: String) = functions.getOrPut(name) {
        val at = "0x%x".format(0x401000 + 0x10 * functions.size)
        builder.createEmptyFunction(name, at, 1, DataType.DEFAULT)
    }

    private fun stores(vararg classes: ClassDecl, returnsThis: Boolean = false) =
        VptrStores(classes.toSet(), returnsThis)

    private fun structors(
        storers: Map<String, VptrStores>,
        holders: Map<String, Set<ClassDecl>>,
        calls: Map<String, Set<String>> = emptyMap(),
        constructorsReturnThis: Boolean = true,
    ) = StructorFinder.Reading(
        storers.mapKeys { fn(it.key) },
        calls.entries.associate { (f, called) -> fn(f) to called.mapTo(mutableSetOf(), ::fn) },
    ).roles(
        holders.mapKeys {
            fn(it.key)
        },
        convention(constructorsReturnThis),
    ).mapKeys { it.key.name }

    private fun convention(returnsThis: Boolean) = object : StructorConvention {
        override val constructorsReturnThis = returnsThis
    }

    @Test
    fun `a function storing a base's vptr and then its own builds the derived class`() {
        storedClass(setOf(a, b)) mustBe b
        storedClass(setOf(a, x)).mustBeNull()
    }

    @Test
    fun `constructors return this, destructors don't, and the slot that calls one deletes`() {
        val storers = mapOf("ctor" to stores(a, returnsThis = true), "dtor" to stores(a))
        val found = structors(storers, mapOf("slot" to setOf(a, b)), mapOf("slot" to setOf("dtor", "free", FREE)))
        found mustBe mapOf(
            "ctor" to (a to CONSTRUCTOR),
            "dtor" to (a to DESTRUCTOR),
            "slot" to (a to DELETING_DESTRUCTOR),
        )
    }

    @Test
    fun `a slot storing the vptr itself has the destructor inlined`() {
        val storers = mapOf(
            "slot" to stores(a, b, returnsThis = true),
            "ctor" to stores(a, b, returnsThis = true),
        )
        structors(storers, mapOf("slot" to setOf(b)), mapOf("slot" to setOf(FREE))) mustBe mapOf(
            "slot" to (b to DELETING_DESTRUCTOR),
            "ctor" to (b to CONSTRUCTOR),
        )
    }

    @Test
    fun `a derived class's destructor with nothing to do leaves only its base's vptr store`() {
        // B's deleting destructor, in B's table alone, calls a destructor that stores A's vptr
        val found =
            structors(mapOf("dtor" to stores(a)), mapOf("slot" to setOf(b)), mapOf("slot" to setOf("dtor", FREE)))
        found mustBe mapOf("slot" to (b to DELETING_DESTRUCTOR), "dtor" to (a to DESTRUCTOR))
    }

    @Test
    fun `a slot calling a constructor, as a clone does, deletes nothing`() {
        val storers = mapOf("ctor" to stores(a, returnsThis = true))
        structors(storers, mapOf("clone" to setOf(a)), mapOf("clone" to setOf("ctor")))["clone"].mustBeNull()
    }

    @Test
    fun `without constructors returning this, what destructors call destroys and every other storer builds`() {
        // `dtor` calls the base's destructor; `ctor` the base's constructor
        val storers = mapOf("ctor" to stores(b), "dtor" to stores(b), "baseCtor" to stores(a), "baseDtor" to stores(a))
        val calls = mapOf("slot" to setOf("dtor", FREE), "dtor" to setOf("baseDtor"), "ctor" to setOf("baseCtor"))
        structors(storers, mapOf("slot" to setOf(b)), calls, false) mustBe mapOf(
            "slot" to (b to DELETING_DESTRUCTOR),
            "dtor" to (b to DESTRUCTOR),
            "baseDtor" to (a to DESTRUCTOR),
            "ctor" to (b to CONSTRUCTOR),
            "baseCtor" to (a to CONSTRUCTOR),
        )
    }

    @Test
    fun `a slot that destroys without freeing is a destructor, as Itanium's complete one is`() {
        // `D1` stores the vptr and frees nothing; `D0` calls it and frees
        val storers = mapOf("d1" to stores(a), "ctor" to stores(a))
        val found =
            structors(storers, mapOf("d1" to setOf(a), "d0" to setOf(a)), mapOf("d0" to setOf("d1", FREE)), false)
        found mustBe mapOf("d1" to (a to DESTRUCTOR), "d0" to (a to DELETING_DESTRUCTOR), "ctor" to (a to CONSTRUCTOR))
    }

    private companion object {
        // As Ghidra's demangler names it
        const val FREE = "operator_delete"
    }
}
