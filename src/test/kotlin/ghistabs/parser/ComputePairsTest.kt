package ghistabs.parser

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class ComputePairsTest {
    @Test
    fun `testLocalsFilteredByRecordIndex filters locals by recordIndex`() {
        val scopeBrackets = listOf(
            Triple(StabType.N_LBRAC, 100L, 3),
            Triple(StabType.N_LBRAC, 200L, 8),
            Triple(StabType.N_RBRAC, 300L, 12),
            Triple(StabType.N_RBRAC, 400L, 20),
        )

        val locals = listOf(
            LocalRecord(createDummyLocal("loc1"), 1000L, 5),
            LocalRecord(createDummyLocal("loc2"), 2000L, 10),
            LocalRecord(createDummyLocal("loc3"), 3000L, 15),
        )

        val pairs = ScopePairs.compute(scopeBrackets, locals)

        Assertions.assertEquals(2, pairs.size)

        val (innerOpen, innerClose, innerLocals) = pairs[0]
        Assertions.assertEquals(200L, innerOpen)
        Assertions.assertEquals(300L, innerClose)
        Assertions.assertEquals(1, innerLocals.size)
        Assertions.assertEquals("loc2", innerLocals[0].decl.name)

        val (outerOpen, outerClose, outerLocals) = pairs[1]
        Assertions.assertEquals(100L, outerOpen)
        Assertions.assertEquals(400L, outerClose)
        Assertions.assertEquals(3, outerLocals.size)
    }

    @Test
    fun `testNestedScopesEachGetTheirOwn isolates nested scopes`() {
        val scopeBrackets = listOf(
            Triple(StabType.N_LBRAC, 100L, 1),
            Triple(StabType.N_RBRAC, 200L, 2),
            Triple(StabType.N_LBRAC, 300L, 5),
            Triple(StabType.N_RBRAC, 400L, 6),
        )

        val locals = listOf(
            LocalRecord(createDummyLocal("a"), 1000L, 1),
            LocalRecord(createDummyLocal("b"), 2000L, 5),
        )

        val pairs = ScopePairs.compute(scopeBrackets, locals)

        Assertions.assertEquals(2, pairs.size)
        Assertions.assertEquals(1, pairs[0].third.size)
        Assertions.assertEquals("a", pairs[0].third[0].decl.name)
        Assertions.assertEquals(1, pairs[1].third.size)
        Assertions.assertEquals("b", pairs[1].third[0].decl.name)
    }

    private fun createDummyLocal(name: String): SymbolDecl.StackLocal<GlobalTypeId> =
        SymbolDecl.StackLocal(name, TypeDecl.Complex(0, 1))
}
