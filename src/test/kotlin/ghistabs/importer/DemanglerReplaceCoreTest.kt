package ghistabs.importer

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.TypedefDataType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for [DemanglerReplacer.decide].
 *
 * On real Ghidra DataTypes rather than stand-in records: they are plain objects, so building and
 * walking them needs no `Application.initialize()` and this stays an ordinary unit test. The planner
 * then sees exactly what production hands it — `numComponents`, `pathName` and the TypeDef check are
 * the real ones, not a hand-maintained mirror that can drift from them.
 */
class DemanglerReplaceCoreTest {
    private fun stub(path: String, name: String): Structure = StructureDataType(CategoryPath(path), name, 0)

    /** A non-empty structure — the shape [DemanglerReplacer.decide] must leave alone. */
    private fun filled(path: String, name: String): Structure =
        StructureDataType(CategoryPath(path), name, 0).apply { add(PointerDataType(), "p", null) }

    @Test
    fun replacesAnEmptyStubThatHasACandidate() {
        val foo = stub("/Demangler", "Foo")
        val real = filled("/proj", "Foo")

        val (ops, skips) = DemanglerReplacer.decide(listOf(foo), mapOf("Foo" to real))

        assertTrue(skips.isEmpty(), "no skips expected")
        assertSame(foo, ops.single().first)
        assertSame(real, ops.single().second)
    }

    @Test
    fun skipsAStubWithNoCandidate() {
        val (ops, skips) = DemanglerReplacer.decide(listOf(stub("/Demangler", "Foo")), emptyMap())

        assertTrue(ops.isEmpty())
        assertInstanceOf(Skip.NoReplacement::class.java, skips.single())
    }

    @Test
    fun leavesANonEmptyStubAlone() {
        val foo = filled("/Demangler", "Foo")

        val (ops, skips) = DemanglerReplacer.decide(listOf(foo), mapOf("Foo" to filled("/proj", "Foo")))

        assertTrue(ops.isEmpty(), "a stub with components is already resolved")
        assertTrue(skips.isEmpty(), "and is not a degradation either")
    }

    /** Foo→Bar where Bar transitively contains Foo would make the type contain itself post-replace. */
    @Test
    fun skipsAReplacementThatWouldContainTheStub() {
        val foo = stub("/Demangler", "Foo")
        val cyclic = StructureDataType(CategoryPath("/proj"), "Foo", 0)
            .apply { add(PointerDataType(foo), "back", null) }

        val (ops, skips) = DemanglerReplacer.decide(listOf(foo), mapOf("Foo" to cyclic))

        assertTrue(ops.isEmpty())
        assertInstanceOf(Skip.WouldBeCycle::class.java, skips.single())
    }

    /**
     * The cycle guard's one exemption, and the reason it exists: `std::string` → `basic_string<…>`
     * yields a typedef→struct→typedef graph that is self-containing on paper but which
     * `replaceDataType` handles (render-backlog §14). A typedef replacement must go through even
     * when its target reaches back to the stub — the branch the record-based tests never reached,
     * because every one of them took `isTypedef`'s default.
     */
    @Test
    fun aTypedefReplacementIsExemptFromTheCycleGuard() {
        val stringStub = stub("/Demangler/std", "string")
        val basicString = StructureDataType(CategoryPath("/std"), "basic_string", 0)
            .apply { add(PointerDataType(stringStub), "self", null) }
        val alias: DataType = TypedefDataType(CategoryPath("/std"), "string", basicString)

        val (ops, skips) = DemanglerReplacer.decide(listOf(stringStub), mapOf("string" to alias))

        assertTrue(skips.isEmpty(), "a typedef replacement must not trip the cycle guard")
        assertSame(alias, ops.single().second)
    }

    @Test
    fun reportsEachStubIndependently() {
        val foo = stub("/Demangler", "Foo")
        val bar = stub("/Demangler", "Bar")
        val baz = stub("/Demangler", "Baz")
        val cyclicBaz = StructureDataType(CategoryPath("/proj"), "Baz", 0)
            .apply { add(PointerDataType(baz), "b", null) }

        val (ops, skips) = DemanglerReplacer.decide(
            listOf(foo, bar, baz),
            mapOf("Foo" to filled("/proj", "Foo"), "Baz" to cyclicBaz),
        )

        assertEquals(listOf(foo), ops.map { it.first })
        assertEquals(listOf(Skip.NoReplacement("Bar"), Skip.WouldBeCycle("Baz")), skips)
    }
}
