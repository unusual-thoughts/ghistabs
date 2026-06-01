package ghistabs.parser

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class ComputePairsTest {
    @Test
    fun `testLocalsFilteredByRecordIndex filters locals by recordIndex`() {
        // Create scope brackets: outer (recordIndex 3..20), inner (recordIndex 8..12)
        val scopeBrackets = listOf(
            Triple(StabType.N_LBRAC, 100L, 3), // outer open
            Triple(StabType.N_LBRAC, 200L, 8), // inner open
            Triple(StabType.N_RBRAC, 300L, 12), // inner close
            Triple(StabType.N_RBRAC, 400L, 20), // outer close
        )

        // Create locals at recordIndex 5, 10, 15
        val locals = listOf(
            LocalRecord(createDummyLocal("loc1"), 1000L, 5),
            LocalRecord(createDummyLocal("loc2"), 2000L, 10),
            LocalRecord(createDummyLocal("loc3"), 3000L, 15),
        )

        // Compute pairs
        val pairs = ScopePairs.compute(scopeBrackets, locals)

        // Should have 2 pairs (inner and outer)
        Assertions.assertEquals(2, pairs.size)

        // First pair should be inner scope (recordIndex 8..12) with only loc2
        val (innerOpen, innerClose, innerLocals) = pairs[0]
        Assertions.assertEquals(200L, innerOpen)
        Assertions.assertEquals(300L, innerClose)
        Assertions.assertEquals(1, innerLocals.size)
        Assertions.assertEquals("loc2", innerLocals[0].decl.name)

        // Second pair should be outer scope (recordIndex 3..20) with all three locals
        val (outerOpen, outerClose, outerLocals) = pairs[1]
        Assertions.assertEquals(100L, outerOpen)
        Assertions.assertEquals(400L, outerClose)
        Assertions.assertEquals(3, outerLocals.size)
    }

    @Test
    fun `testNestedScopesEachGetTheirOwn isolates nested scopes`() {
        // Two independent nested scopes
        val scopeBrackets = listOf(
            Triple(StabType.N_LBRAC, 100L, 1), // scope1 open
            Triple(StabType.N_RBRAC, 200L, 2), // scope1 close
            Triple(StabType.N_LBRAC, 300L, 5), // scope2 open
            Triple(StabType.N_RBRAC, 400L, 6), // scope2 close
        )

        val locals = listOf(
            LocalRecord(createDummyLocal("a"), 1000L, 1),
            LocalRecord(createDummyLocal("b"), 2000L, 5),
        )

        val pairs = ScopePairs.compute(scopeBrackets, locals)

        Assertions.assertEquals(2, pairs.size)
        // First pair: scope1 gets local "a"
        Assertions.assertEquals(1, pairs[0].third.size)
        Assertions.assertEquals("a", pairs[0].third[0].decl.name)
        // Second pair: scope2 gets local "b"
        Assertions.assertEquals(1, pairs[1].third.size)
        Assertions.assertEquals("b", pairs[1].third[0].decl.name)
    }

    private fun createDummyLocal(name: String): SymbolDecl.StackLocal = SymbolDecl.StackLocal(name, TypeDecl.Builtin)
}
