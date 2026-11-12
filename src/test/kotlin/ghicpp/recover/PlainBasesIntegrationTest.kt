package ghicpp.recover

import ghicpp.ClassDecl
import ghicpp.dissect.DissectionCache
import ghicpp.dissect.Dissections
import ghicpp.dissect.VptrStores
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

/** [BaseCandidates.inferBases] off what structors store and call, read by hand. */
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
        slots: Map<String, List<String?>> = emptyMap(),
    ): Map<String, List<Pair<String, Long?>>> {
        val uses = Dissections(
            (stores.keys + calls.keys).associate {
                fn(it) to DissectionCache.Dissection(
                    stores[it]?.let { cs -> VptrStores(cs.mapTo(mutableSetOf(), ::cls)) },
                    calls[it]?.let { byOffset ->
                        byOffset.mapValues { (_, called) -> called.mapTo(mutableSetOf(), ::fn) }
                    }.orEmpty(),
                )
            },
        )
        val tables: Map<ClassDecl, List<Function?>> =
            slots.entries.associate { (c, fs) -> cls(c) to fs.map { it?.let(::fn) } }
        BaseCandidates(tables).inferBases(classes.values, uses)
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
        bases(mapOf("ctor" to setOf("A", "B")), slots = mapOf("A" to unique("a", 2), "B" to unique("b", 3))) mustBe
            mapOf("B" to listOf("A" to 0L))
        classes.clear()
        bases(mapOf("ctor" to setOf("X", "Y")), slots = mapOf("X" to unique("x", 2), "Y" to unique("y", 2))) mustBe
            emptyMap()
    }

    /** [n] slots of functions no other table holds. */
    private fun unique(prefix: String, n: Int) = (1..n).map { "$prefix$it" }

    @Test
    fun `a function tables share in one slot was introduced by the shortest, which each other derives from`() {
        // B adds b3, which D inherits; X adds nothing but overrides x1, as each of them does.
        val slots = mapOf(
            "A" to listOf("a1", "a2"),
            "B" to listOf("b1", "a2", "b3"),
            "D" to listOf("d1", "a2", "b3", "d4"),
            "X" to listOf("x1", "a2", "x3"),
        )
        bases(emptyMap(), slots = slots) mustBe mapOf(
            "B" to listOf("A" to 0L),
            "D" to listOf("B" to 0L),
            "X" to listOf("A" to 0L),
        )
    }

    @Test
    fun `a function in different slots, folded, a tie for the shortest and a null say nothing`() {
        val slots = mapOf(
            "A" to listOf("a1", "folded"),
            "B" to listOf("folded", "b2", "b3"),
            "X" to listOf("x1", "tie", null),
            "Y" to listOf("y1", "tie", null),
        )
        bases(emptyMap(), slots = slots) mustBe emptyMap()
    }

    @Test
    fun `a class doesn't derive from one overriding a slot it inherits unchanged from further up`() {
        // X overrides a2; Y keeps A's, so it can't derive from X though it shares x3 with it.
        val slots = mapOf(
            "A" to listOf("a1", "a2"),
            "X" to listOf("x1", "x2", "x3"),
            "Y" to listOf("y1", "a2", "x3", "y4"),
        )
        bases(emptyMap(), slots = slots) mustBe mapOf("Y" to listOf("A" to 0L))
    }

    @Test
    fun `two classes whose structors call each other's derive from neither`() {
        bases(
            mapOf("aCtor" to setOf("A"), "bCtor" to setOf("B")),
            mapOf("aCtor" to mapOf(0L to setOf("bCtor")), "bCtor" to mapOf(0L to setOf("aCtor"))),
        ) mustBe emptyMap()
    }
}
