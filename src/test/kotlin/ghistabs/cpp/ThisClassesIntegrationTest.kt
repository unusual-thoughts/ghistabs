package ghistabs.cpp

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
class ThisClassesIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val functions = mutableMapOf<String, Function>()

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("this-classes", ProgramBuilder._X86)
        builder.createMemory(".text", "0x401000", 0x1000)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun fn(name: String) = functions.getOrPut(name) {
        val at = "0x%x".format(0x401000 + 0x10 * functions.size)
        builder.createEmptyFunction(name, at, 1, DataType.DEFAULT)
    }

    // class B : A; class C : A; class D : B, each by a namespace id
    private val bases = mapOf(A to null, B to A, C to A, D to B)
    private fun chain(cls: Long) = generateSequence(cls) { bases[it] }.toList()

    private val slots = mapOf(A to 2, B to 3, C to 2, D to 3)

    private fun call(caller: String, callee: String, built: Long? = null) = ThisCall(fn(caller), fn(callee), built)

    private fun use(extent: Long, vararg slots: Int, calls: Set<String> = emptySet()) =
        ThisUse(extent, slots.toSet(), calls.mapTo(mutableSetOf(), ::fn))

    private fun guess(
        calls: List<ThisCall>,
        known: Map<String, Long> = mapOf("a" to A, "b" to B, "c" to C, "d" to D),
        uses: Map<String, ThisUse> = emptyMap(),
        exactSize: (Long) -> Long? = { null },
    ) = guessThisClasses(
        calls.mapTo(mutableSetOf()) { it.callee },
        known.mapKeys { fn(it.key) },
        calls,
        uses.mapKeys { fn(it.key) },
        ::chain,
        slots::get,
        exactSize = exactSize,
    ).mapKeys { it.key.name }

    @Test
    fun `a function called on a method's this belongs to that method's class`() {
        guess(listOf(call("d", "f")))["f"]?.cls mustBe D
    }

    @Test
    fun `a function called on objects of sibling classes belongs to their common base`() {
        guess(listOf(call("b", "f"), call("c", "f")))["f"] mustBe ThisClassGuess(A, A, 2)
        guess(listOf(call("d", "f"), call("b", "f")))["f"]?.cls mustBe B
    }

    @Test
    fun `an object a constructor built counts as that class, and an unknown caller not at all`() {
        guess(listOf(call("x", "f", built = C), call("y", "f")))["f"] mustBe ThisClassGuess(C, C, 1)
        guess(listOf(call("y", "f")))["f"].mustBeNull()
    }

    @Test
    fun `a guess moves up to a base that does all the function does`() {
        val known = mapOf("d" to D, "aCtor" to A, "bCtor" to B)
        val uses = mapOf("aCtor" to use(8), "bCtor" to use(16))
        fun refined(use: ThisUse) = guess(listOf(call("d", "f")), known, uses + ("f" to use))["f"]?.cls

        refined(use(8, 1)) mustBe A
        // reaches past A's own fields, or calls a slot A's vftable doesn't have
        refined(use(12)) mustBe B
        refined(use(8, 2)) mustBe B
        // reaches past what the methods of every base reach
        refined(use(20)) mustBe D
        // calls a method of B's on this
        refined(use(4, calls = setOf("bCtor"))) mustBe B
    }

    @Test
    fun `an exact size lets a guess move up to a base, and rules out a class too small`() {
        val sizes = mapOf(A to 8L, B to 12L, D to 16L)
        fun guessed(extent: Long) =
            guess(listOf(call("d", "f")), mapOf("d" to D), mapOf("f" to use(extent)), sizes::get)["f"]?.cls

        // no method of A's or B's reaches anywhere, but their sizes are known
        guessed(8) mustBe A
        guessed(12) mustBe B
        // past D's own size: none of D's
        guessed(20).mustBeNull()
    }

    @Test
    fun `a guess makes its function's own calls on this evidence for the next round`() {
        guess(listOf(call("d", "f"), call("f", "g")))["g"]?.cls mustBe D
    }

    private companion object {
        const val A = 1L
        const val B = 2L
        const val C = 3L
        const val D = 4L
    }
}
