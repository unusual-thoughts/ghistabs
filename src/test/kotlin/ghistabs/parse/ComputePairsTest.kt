package ghistabs.parse

import ghistabs.harvest.SymbolRecord
import ghistabs.importer.ScopePairs
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
            SymbolRecord(
                recordIndex = 5,
                recordType = StabType.N_LSYM,
                body = createDummyLocal("loc1"),
                rawValue = 1000L,
            ),
            SymbolRecord(
                recordIndex = 10,
                recordType = StabType.N_LSYM,
                body = createDummyLocal("loc2"),
                rawValue = 2000L,
            ),
            SymbolRecord(
                recordIndex = 15,
                recordType = StabType.N_LSYM,
                body = createDummyLocal("loc3"),
                rawValue = 3000L,
            ),
        )

        val pairs = ScopePairs.compute(scopeBrackets, locals)

        Assertions.assertEquals(2, pairs.size)

        val (innerOpen, innerClose, innerLocals) = pairs[0]
        Assertions.assertEquals(200L, innerOpen)
        Assertions.assertEquals(300L, innerClose)
        Assertions.assertEquals(1, innerLocals.size)
        Assertions.assertEquals("loc2", innerLocals[0].body.name)

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
            SymbolRecord(recordIndex = 1, recordType = StabType.N_LSYM, body = createDummyLocal("a"), rawValue = 1000L),
            SymbolRecord(recordIndex = 5, recordType = StabType.N_LSYM, body = createDummyLocal("b"), rawValue = 2000L),
        )

        val pairs = ScopePairs.compute(scopeBrackets, locals)

        Assertions.assertEquals(2, pairs.size)
        Assertions.assertEquals(1, pairs[0].third.size)
        Assertions.assertEquals("a", pairs[0].third[0].body.name)
        Assertions.assertEquals(1, pairs[1].third.size)
        Assertions.assertEquals("b", pairs[1].third[0].body.name)
    }

    private fun createDummyLocal(name: String): SymbolDecl.StackLocal<GlobalTypeId> =
        SymbolDecl.StackLocal(name, TypeDecl.Complex(0, 1))
}
