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
        a to ThisClassShape(null, sizes[a]),
        b to ThisClassShape(a, sizes[b]),
        c to ThisClassShape(a, sizes[c]),
        d to ThisClassShape(b, sizes[d]),
    )

    private fun call(caller: String, callee: String, built: GhidraClass? = null) =
        ThisCall(fn(caller), fn(callee), built)

    private fun guess(
        calls: List<ThisCall>,
        extents: Map<String, Long> = emptyMap(),
        sizes: Map<GhidraClass, LongRange> = emptyMap(),
    ) = ThisClassGuesser(shapes(sizes))
        .guess(ThisReading(extents.map { (f, extent) -> fn(f) to ThisUse(extent) }.toMap(), calls))
        .mapKeys { it.key.name }

    @Test
    fun `a function called on a method's this belongs to that method's class`() {
        guess(listOf(call("d", "f")))["f"] mustBe ThisClassGuess(d, 1)
    }

    @Test
    fun `a function called on a class and on classes derived from it belongs to that class`() {
        guess(listOf(call("d", "f"), call("b", "f"), call("d", "f")))["f"] mustBe ThisClassGuess(b, 3)
    }

    @Test
    fun `a function called on sibling classes belongs to neither, nor to their common base`() {
        guess(listOf(call("b", "f"), call("c", "f")))["f"].mustBeNull()
    }

    @Test
    fun `an object a constructor built counts as that class, and an unknown caller not at all`() {
        guess(listOf(call("x", "f", built = c), call("y", "f")))["f"] mustBe ThisClassGuess(c, 1)
        guess(listOf(call("y", "f")))["f"].mustBeNull()
    }

    @Test
    fun `a function reaching past its class's exact size is none of its`() {
        val sizes = mapOf(d to 16L..16L)
        guess(listOf(call("d", "f")), mapOf("f" to 16), sizes)["f"]?.cls mustBe d
        guess(listOf(call("d", "f")), mapOf("f" to 20), sizes)["f"].mustBeNull()
    }

    @Test
    fun `a guess is no evidence for another`() {
        guess(listOf(call("d", "f"), call("f", "g")))["g"].mustBeNull()
    }
}
