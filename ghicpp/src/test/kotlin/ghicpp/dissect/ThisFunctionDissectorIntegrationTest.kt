package ghicpp.dissect

import ghicpp.ClassDecl
import ghicpp.StructorConvention
import ghicpp.StructorRole.*
import ghicpp.TestClass
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeNull
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

    /** What a storer of [classes]' vptrs does: [pre] and [post] on `this` + 0 around the store, then [members]. */
    private class Storer(
        val classes: Set<ClassDecl>,
        val pre: Set<String>,
        val post: Set<String>,
        val members: List<Long>,
    )

    /**
     * A function storing [classes]' vptrs at `this` + 0, calling the functions named [pre] and [post] on `this` + 0
     * around the store, and after them a function on each of [members], an offset into `this`, in that order.
     */
    private fun stores(
        vararg classes: ClassDecl,
        pre: Set<String> = emptySet(),
        post: Set<String> = emptySet(),
        members: List<Long> = emptyList(),
    ) = Storer(classes.toSet(), pre, post, members)

    private fun structors(
        storers: Map<String, Storer>,
        holders: Map<String, Set<ClassDecl>>,
        calls: Map<String, Set<String>> = emptyMap(),
    ) = Dissections(
        (storers.keys + calls.keys).associate {
            val byOffset = calls[it]?.let { called -> mapOf(0L to called.mapTo(mutableSetOf(), ::fn)) }.orEmpty()
            fn(it) to (
                storers[it]?.let { s ->
                    builder.program.storer(
                        s.classes,
                        s.pre.map { g -> 0L to fn(g) },
                        s.post.map { g -> 0L to fn(g) } + s.members.map { o -> o to fn("member$o") },
                        byOffset,
                    )
                } ?: DissectionCache.Dissection(subobjectCalls = byOffset)
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
            "ctor" to stores(b, pre = setOf("baseCtor")),
            "dtor" to stores(b, post = setOf("baseDtor")),
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
            "ctor" to stores(b, pre = setOf("baseCtor"), post = setOf("baseDtor")),
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

    @Test
    fun `a storer that calls on its members from the last down destroys, and one calling up builds`() {
        // X's destructor isn't virtual, and its base and members leave no other trace: a constructor builds the
        // members in the order they are laid, and a destructor destroys them the other way
        val storers = mapOf(
            "ctor" to stores(x, members = listOf(4, 8)),
            "dtor" to stores(x, members = listOf(8, 4)),
        )
        structors(storers, emptyMap()) mustBe mapOf("ctor" to (x to CONSTRUCTOR), "dtor" to (x to DESTRUCTOR))
    }

    @Test
    fun `a landing pad destroying a member again still leaves the order its first calls take`() {
        // The constructor's pad destroys the member at 4 where the one at 8 throws; the destructor's where 8's does
        val storers = mapOf(
            "ctor" to stores(x, members = listOf(4, 8, 4)),
            "dtor" to stores(x, members = listOf(8, 4, 4)),
        )
        structors(storers, emptyMap()) mustBe mapOf("ctor" to (x to CONSTRUCTOR), "dtor" to (x to DESTRUCTOR))
    }

    @Test
    fun `a constructor's body calling a method on this after building its members still builds`() {
        // The method, on `this` + 0, comes after the member at 0x28; the destructor destroys 8, then 4
        val storers = mapOf(
            "ctor" to stores(x, members = listOf(0x28, 0x28, 0)),
            "dtor" to stores(x, members = listOf(0, 8, 4)),
        )
        structors(storers, emptyMap()) mustBe mapOf("ctor" to (x to CONSTRUCTOR), "dtor" to (x to DESTRUCTOR))
    }

    @Test
    fun `the order of a storer's member calls decides only what nothing else does`() {
        // B's constructor calls A's before its store, then on its members from the last down
        val storers = mapOf(
            "ctor" to stores(b, pre = setOf("baseCtor"), members = listOf(8, 4)),
            "baseCtor" to stores(a),
        )
        structors(storers, emptyMap())["ctor"] mustBe (b to CONSTRUCTOR)
    }

    /**
     * The classes [Dissections] takes each function to store the vptr of where it belongs, off one function storing
     * the primary table of [stored] through a vbtable at `this` + 12 and calling `vbaseCtor` there, which stores
     * [vbase]'s table at its `this` + 0.
     */
    private fun storedThroughVbtable(stored: ClassDecl, vbase: ClassDecl): Map<String, Set<ClassDecl>> {
        val at = builder.program.addressFactory.defaultAddressSpace.getAddress(0x500000L)
        return Dissections(
            mapOf(
                fn("ctor") to DissectionCache.Dissection(
                    listOf(VptrStore(at, 12, stored, 0, throughVbtable = true)),
                    mapOf(12L to setOf(fn("vbaseCtor"))),
                ),
                fn("vbaseCtor") to builder.program.storer(setOf(vbase)),
            ),
        ).stores.map { (f, ss) -> f.name to ss.classes }.toMap()
    }

    @Test
    fun `a table stored only through a vbtable is where it belongs, the class having no vfptr of its own`() {
        // struct Down : virtual Core { int f(); }: MSVC gives Down no vfptr, only its table for Core at +12
        storedThroughVbtable(b, a)["ctor"] mustBe setOf(b)
    }

    @Test
    fun `a table the virtual base's own constructor stores is that base's, stored through the vbtable or not`() {
        storedThroughVbtable(a, a)["ctor"] mustBe emptySet()
    }

    private companion object {
        // As Ghidra's demangler names it
        const val FREE = "operator_delete"
    }
}
