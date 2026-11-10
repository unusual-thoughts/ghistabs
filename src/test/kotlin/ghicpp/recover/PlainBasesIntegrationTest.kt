package ghicpp.recover

import ghicpp.ClassDecl
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/** [inferBases] off what structors store and call, read by hand. */
@Tag("integration")
class PlainBasesIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val functions = mutableMapOf<String, Function>()
    private val classes = mutableMapOf<String, PlainClass>()

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("plain-bases", ProgramBuilder._X86)
        builder.createMemory(".text", "0x401000", 0x1000)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun fn(name: String) = functions.getOrPut(name) {
        val at = "0x%x".format(0x401000 + 0x10 * functions.size)
        builder.createEmptyFunction(name, at, 1, DataType.DEFAULT)
    }

    private fun cls(name: String) = classes.getOrPut(name) {
        lateinit var ns: ghidra.program.model.listing.GhidraClass
        builder.withTransaction { ns = builder.program.symbolTable.createClass(null, name, SourceType.ANALYSIS) }
        PlainClass(ns, emptyList())
    }

    /**
     * The bases [inferBases] gives each class, by name and offset, off functions storing the vptrs of the
     * classes [stores] names and calling the functions [calls] names at `this` + the offset each gives.
     */
    private fun bases(
        stores: Map<String, Set<String>>,
        calls: Map<String, Map<Long, Set<String>>> = emptyMap(),
        slots: Map<String, Int> = emptyMap(),
    ): Map<String, List<Pair<String, Long?>>> {
        val reading = StructorFinder.Reading(
            stores.entries.associate { (f, cs) -> fn(f) to VptrStores(cs.mapTo(mutableSetOf(), ::cls)) },
            calls.entries.associate { (f, byOffset) ->
                fn(f) to byOffset.mapValues { (_, called) -> called.mapTo(mutableSetOf(), ::fn) }
            },
        )
        val counts: Map<ClassDecl, Int> = slots.mapKeys { cls(it.key) }
        inferBases(classes.values, reading, counts)
        return classes.values.filter { it.bases.isNotEmpty() }
            .associate { c -> c.name to c.bases.map { it.cls.name to it.offset } }
    }

    @Test
    fun `a structor calling another class's on this makes that class its base, and on a member nothing`() {
        bases(
            mapOf("dCtor" to setOf("D"), "bCtor" to setOf("B"), "cCtor" to setOf("C")),
            mapOf("dCtor" to mapOf(0L to setOf("bCtor"), 8L to setOf("cCtor"))),
        ) mustBe mapOf("D" to listOf("B" to 0L))
    }

    @Test
    fun `of a chain of structor calls only the nearest is a direct base`() {
        // D's constructor calls B's, which calls A's; D's also inlines a call to A's.
        bases(
            mapOf("dCtor" to setOf("D"), "bCtor" to setOf("B"), "aCtor" to setOf("A")),
            mapOf("dCtor" to mapOf(0L to setOf("bCtor", "aCtor")), "bCtor" to mapOf(0L to setOf("aCtor"))),
        ) mustBe mapOf("D" to listOf("B" to 0L), "B" to listOf("A" to 0L))
    }

    @Test
    fun `vptrs stored together go base first by their tables' lengths, and a tie says nothing`() {
        bases(mapOf("ctor" to setOf("A", "B")), slots = mapOf("A" to 2, "B" to 3)) mustBe
            mapOf("B" to listOf("A" to 0L))
        classes.clear()
        bases(mapOf("ctor" to setOf("X", "Y")), slots = mapOf("X" to 2, "Y" to 2)) mustBe emptyMap()
    }

    @Test
    fun `two classes whose structors call each other's derive from neither`() {
        bases(
            mapOf("aCtor" to setOf("A"), "bCtor" to setOf("B")),
            mapOf("aCtor" to mapOf(0L to setOf("bCtor")), "bCtor" to mapOf(0L to setOf("aCtor"))),
        ) mustBe emptyMap()
    }
}
