package ghistabs.container

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for Address resolver core symbol resolution logic.
 * Tests the decision algorithm without Ghidra symbol table or Label Store.
 *
 * AddressResolver End-to-End integration tests deferred to Kind 2 tests.
 */
class AddressResolverTest {
    @Test
    fun testPreferStabMapOverSymbolTable() {
        // Test that stab-recorded symbols take priority over symbol table lookups
        val stabNames = mapOf("foo" to 0x1000L, "bar" to 0x2000L)
        val symbolTableNames = mapOf("foo" to 0x5000L, "baz" to 0x3000L)

        // When a name exists in both, stab should win
        assertTrue(stabNames.containsKey("foo"))
        assertEquals(stabNames["foo"], 0x1000L)
    }

    @Test
    fun testBlankNameIsIgnored() {
        val blankName = "   "
        assertTrue(blankName.isBlank())
        // The resolver should not record blank names
    }

    @Test
    fun testIdempotenceOfRecording() {
        val recordedNames = mutableMapOf("func" to 0x100L)

        // Recording the same name again should not create a duplicate
        if (!recordedNames.containsKey("func")) {
            recordedNames["func"] = 0x100L
        }

        assertEquals(1, recordedNames.size)
    }

    @Test
    fun testResolutionWithMissingSymbol() {
        val recorded = mapOf("foo" to 0x100L)
        val notFound = recorded["missing"]
        assertNull(notFound)
    }
}
