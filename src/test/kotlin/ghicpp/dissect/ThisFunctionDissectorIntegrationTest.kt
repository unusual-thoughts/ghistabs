package ghicpp.dissect

import ghicpp.ClassDecl
import ghicpp.TestClass
import ghicpp.abi.StructorConvention
import ghicpp.abi.StructorRole.*
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("integration")
class ThisFunctionDissectorIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
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

    /** A function storing [classes]' vptrs, calling the functions named [before] and [after] around the stores. */
    private fun stores(vararg classes: ClassDecl, before: Set<String> = emptySet(), after: Set<String> = emptySet()) =
        VptrStores(classes.toSet(), before.mapTo(mutableSetOf(), ::fn), after.mapTo(mutableSetOf(), ::fn))

    private fun structors(
        storers: Map<String, VptrStores>,
        holders: Map<String, Set<ClassDecl>>,
        calls: Map<String, Set<String>> = emptyMap(),
    ) = Dissections(
        (storers.keys + calls.keys).associate {
            fn(it) to DissectionCache.Dissection(
                storers[it],
                calls[it]?.let { called -> mapOf(0L to called.mapTo(mutableSetOf(), ::fn)) }.orEmpty(),
            )
        },
    ).roles(holders.mapKeys { fn(it.key) }, object : StructorConvention {}).mapKeys { it.key.name }

    @Test
    fun `a function storing a base's vptr and then its own builds the derived class`() {
        storedClass(setOf(a, b)) mustBe b
        storedClass(setOf(a, x)).mustBeNull()
    }

    @Test
    fun `the slot that calls a destructor and frees deletes, and a storer nothing sorts builds`() {
        val storers = mapOf("ctor" to stores(a), "dtor" to stores(a))
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
            "slot" to stores(a, b),
            "ctor" to stores(a, b),
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
    fun `a deleting destructor's callee destroys though it stores no vptr, its base's destructor storing it`() {
        // B's destructor leaves the vptr to A's, which it calls; B's deleting destructor calls B's
        val storers = mapOf("baseDtor" to stores(a))
        val calls = mapOf("slot" to setOf("dtor", FREE), "dtor" to setOf("baseDtor"))
        structors(storers, mapOf("slot" to setOf(b)), calls) mustBe mapOf(
            "slot" to (b to DELETING_DESTRUCTOR),
            "dtor" to (b to DESTRUCTOR),
            "baseDtor" to (a to DESTRUCTOR),
        )
    }

    @Test
    fun `a deleting destructor calling more than its destructor names none`() {
        val calls = mapOf("slot" to setOf("dtor", "other", FREE))
        structors(emptyMap(), mapOf("slot" to setOf(b)), calls) mustBe emptyMap()
    }

    @Test
    fun `a slot calling a constructor, as a clone does, deletes nothing`() {
        val storers = mapOf("ctor" to stores(a))
        structors(storers, mapOf("clone" to setOf(a)), mapOf("clone" to setOf("ctor")))["clone"].mustBeNull()
    }

    @Test
    fun `what destructors call destroys and every other storer builds`() {
        // `dtor` calls the base's destructor; `ctor` the base's constructor
        val storers = mapOf("ctor" to stores(b), "dtor" to stores(b), "baseCtor" to stores(a), "baseDtor" to stores(a))
        val calls = mapOf("slot" to setOf("dtor", FREE), "dtor" to setOf("baseDtor"), "ctor" to setOf("baseCtor"))
        structors(storers, mapOf("slot" to setOf(b)), calls) mustBe mapOf(
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
            structors(storers, mapOf("d1" to setOf(a), "d0" to setOf(a)), mapOf("d0" to setOf("d1", FREE)))
        found mustBe mapOf("d1" to (a to DESTRUCTOR), "d0" to (a to DELETING_DESTRUCTOR), "ctor" to (a to CONSTRUCTOR))
    }

    @Test
    fun `a storer calling its base's before its stores builds, and one calling it after destroys`() {
        // No slot calls either: B's destructor isn't virtual
        val storers = mapOf(
            "ctor" to stores(b, before = setOf("baseCtor")),
            "dtor" to stores(b, after = setOf("baseDtor")),
            "baseCtor" to stores(a),
            "baseDtor" to stores(a),
        )
        structors(storers, emptyMap()) mustBe mapOf(
            "ctor" to (b to CONSTRUCTOR),
            "baseCtor" to (a to CONSTRUCTOR),
            "dtor" to (b to DESTRUCTOR),
            "baseDtor" to (a to DESTRUCTOR),
        )
    }

    @Test
    fun `a constructor that destroys its built bases where one throws still builds`() {
        // Itanium's landing pads, after the stores, destroy the bases built before them
        val storers = mapOf(
            "ctor" to stores(b, before = setOf("baseCtor"), after = setOf("baseDtor")),
            "baseCtor" to stores(a),
            "baseDtor" to stores(a),
        )
        structors(storers, mapOf("slot" to setOf(a)), mapOf("slot" to setOf("baseDtor", FREE)))["ctor"] mustBe
            (b to CONSTRUCTOR)
    }

    @Test
    fun `a storer calling only known destructors destroys`() {
        // X's destructor destroys a B member, whose destructor B's deleting destructor calls
        val storers = mapOf("dtor" to stores(b), "xDtor" to stores(x), "xCtor" to stores(x))
        val calls = mapOf("slot" to setOf("dtor", FREE), "xDtor" to setOf("dtor"))
        structors(storers, mapOf("slot" to setOf(b)), calls) mustBe mapOf(
            "slot" to (b to DELETING_DESTRUCTOR),
            "dtor" to (b to DESTRUCTOR),
            "xDtor" to (x to DESTRUCTOR),
            "xCtor" to (x to CONSTRUCTOR),
        )
    }

    private companion object {
        // As Ghidra's demangler names it
        const val FREE = "operator_delete"
    }
}
