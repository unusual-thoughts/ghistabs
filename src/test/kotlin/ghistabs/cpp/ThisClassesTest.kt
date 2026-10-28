package ghistabs.cpp

import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import org.junit.jupiter.api.Test

class ThisClassesTest {
    // class B : A; class C : A; class D : B
    private val bases = mapOf("A" to null, "B" to "A", "C" to "A", "D" to "B")
    private fun chain(cls: String) = generateSequence(cls) { bases[it] }.toList()

    private val slots = mapOf("A" to 2, "B" to 3, "C" to 2, "D" to 3)

    private fun guess(
        calls: List<ThisCall<String, String>>,
        known: Map<String, String> = mapOf("a" to "A", "b" to "B", "c" to "C", "d" to "D"),
        uses: Map<String, ThisUse<String>> = emptyMap(),
        candidates: Set<String> = calls.mapTo(mutableSetOf()) { it.callee },
    ) = guessThisClasses(candidates, known, calls, uses, ::chain, slots::get)

    private fun use(extent: Long, vararg slots: Int, calls: Set<String> = emptySet()) =
        ThisUse(extent, slots.toSet(), calls)

    @Test
    fun `a function called on a method's this belongs to that method's class`() {
        guess(listOf(ThisCall("d", "f")))["f"]?.cls mustBe "D"
    }

    @Test
    fun `a function called on objects of sibling classes belongs to their common base`() {
        guess(listOf(ThisCall("b", "f"), ThisCall("c", "f")))["f"] mustBe ThisClassGuess("A", "A", 2)
        guess(listOf(ThisCall("d", "f"), ThisCall("b", "f")))["f"]?.cls mustBe "B"
    }

    @Test
    fun `an object a constructor built counts as that class, and an unknown caller not at all`() {
        guess(listOf(ThisCall("x", "f", built = "C"), ThisCall("y", "f")))["f"] mustBe ThisClassGuess("C", "C", 1)
        guess(listOf(ThisCall("y", "f")))["f"].mustBeNull()
    }

    @Test
    fun `a guess moves up to a base that does all the function does`() {
        val known = mapOf("d" to "D", "aCtor" to "A", "bCtor" to "B")
        val uses = mapOf("aCtor" to use(8), "bCtor" to use(16))
        fun refined(use: ThisUse<String>) = guess(listOf(ThisCall("d", "f")), known, uses + ("f" to use))["f"]?.cls

        refined(use(8, 1)) mustBe "A"
        // reaches past A's own fields, or calls a slot A's vftable doesn't have
        refined(use(12)) mustBe "B"
        refined(use(8, 2)) mustBe "B"
        // reaches past what the methods of every base reach
        refined(use(20)) mustBe "D"
        // calls a method of B's on this
        refined(use(4, calls = setOf("bCtor"))) mustBe "B"
    }

    @Test
    fun `an exact size lets a guess move up to a base, and rules out a class too small`() {
        val sizes = mapOf("A" to 8L, "B" to 12L, "D" to 16L)
        fun guessed(extent: Long) = guessThisClasses(
            setOf("f"),
            mapOf("d" to "D"),
            listOf(ThisCall("d", "f")),
            mapOf("f" to ThisUse(extent, emptySet(), emptySet<String>())),
            ::chain,
            slots::get,
            exactSize = sizes::get,
        )["f"]?.cls

        // no method of A's or B's reaches anywhere, but their sizes are known
        guessed(8) mustBe "A"
        guessed(12) mustBe "B"
        // past D's own size: none of D's
        guessed(20).mustBeNull()
    }

    @Test
    fun `a guess makes its function's own calls on this evidence for the next round`() {
        val calls = listOf<ThisCall<String, String>>(ThisCall("d", "f"), ThisCall("f", "g"))
        guess(calls)["g"]?.cls mustBe "D"
    }
}
