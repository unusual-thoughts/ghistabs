package ghistabs.cpp.recover

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("integration")
class ThisClassesIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val functions = mutableMapOf<String, Function>()

    // class B : A; class C : A; class D : B
    private lateinit var a: GhidraClass
    private lateinit var b: GhidraClass
    private lateinit var c: GhidraClass
    private lateinit var d: GhidraClass

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("this-classes", ProgramBuilder._X86)
        builder.createMemory(".text", "0x401000", 0x1000)
        builder.withTransaction {
            val symbols = builder.program.symbolTable
            fun cls(name: String) = symbols.createClass(null, name, SourceType.USER_DEFINED)
            a = cls("A")
            b = cls("B")
            c = cls("C")
            d = cls("D")
        }
        // A method of each, named after it in lower case.
        listOf(a, b, c, d).forEach { fn(it.name.lowercase(), it) }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    /** A function; a method of [cls] if given. */
    private fun fn(name: String, cls: GhidraClass? = null) = functions.getOrPut(name) {
        val at = "0x%x".format(0x401000 + 0x10 * functions.size)
        builder.createEmptyFunction(name, at, 1, DataType.DEFAULT).also { f ->
            cls?.let { builder.withTransaction { f.parentNamespace = it } }
        }
    }

    private fun shapes(sizes: Map<GhidraClass, LongRange> = emptyMap()) = mapOf(
        a to ThisClassShape(null, sizes[a], 2),
        b to ThisClassShape(a, sizes[b], 3),
        c to ThisClassShape(a, sizes[c], 2),
        d to ThisClassShape(b, sizes[d], 3),
    )

    private fun call(caller: String, callee: String, built: GhidraClass? = null) =
        ThisCall(fn(caller), fn(callee), built)

    private fun use(extent: Long, vararg slots: Int, calls: Set<String> = emptySet()) =
        ThisUse(extent, slots.toSet(), calls.mapTo(mutableSetOf(), ::fn))

    private fun guess(
        calls: List<ThisCall>,
        uses: Map<String, ThisUse> = emptyMap(),
        sizes: Map<GhidraClass, LongRange> = emptyMap(),
    ) = ThisClassGuesser(shapes(sizes)).guess(ThisReading(uses.mapKeys { fn(it.key) }, calls)).mapKeys { it.key.name }

    @Test
    fun `a function called on a method's this belongs to that method's class`() {
        guess(listOf(call("d", "f")))["f"]?.cls mustBe d
    }

    @Test
    fun `a function called on objects of sibling classes belongs to their common base`() {
        guess(listOf(call("b", "f"), call("c", "f")))["f"] mustBe ThisClassGuess(a, a, 2)
        guess(listOf(call("d", "f"), call("b", "f")))["f"]?.cls mustBe b
    }

    @Test
    fun `an object a constructor built counts as that class, and an unknown caller not at all`() {
        guess(listOf(call("x", "f", built = c), call("y", "f")))["f"] mustBe ThisClassGuess(c, c, 1)
        guess(listOf(call("y", "f")))["f"].mustBeNull()
    }

    @Test
    fun `a guess moves up to a base that does all the function does`() {
        fn("aCtor", a)
        fn("bCtor", b)
        val uses = mapOf("aCtor" to use(8), "bCtor" to use(16))
        fun refined(use: ThisUse) = guess(listOf(call("d", "f")), uses + ("f" to use))["f"]?.cls

        refined(use(8, 1)) mustBe a
        // reaches past A's own fields, or calls a slot A's vftable doesn't have
        refined(use(12)) mustBe b
        refined(use(8, 2)) mustBe b
        // reaches past what the methods of every base reach
        refined(use(20)) mustBe d
        // calls a method of B's on this
        refined(use(4, calls = setOf("bCtor"))) mustBe b
    }

    @Test
    fun `an exact size lets a guess move up to a base, and rules out a class too small`() {
        val sizes = mapOf(a to 8L..8L, b to 12L..12L, d to 16L..16L)
        fun guessed(extent: Long) = guess(listOf(call("d", "f")), mapOf("f" to use(extent)), sizes)["f"]?.cls

        // no method of A's or B's reaches anywhere, but their sizes are known
        guessed(8) mustBe a
        guessed(12) mustBe b
        // past D's own size: none of D's
        guessed(20).mustBeNull()
    }

    @Test
    fun `a guess makes its function's own calls on this evidence for the next round`() {
        guess(listOf(call("d", "f"), call("f", "g")))["g"]?.cls mustBe d
    }
}
