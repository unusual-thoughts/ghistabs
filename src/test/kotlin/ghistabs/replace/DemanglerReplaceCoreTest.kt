package ghistabs.replace

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for DemanglerReplaceCore.
 * No Ghidra imports, no mockito — operates entirely on POKOs.
 */
class DemanglerReplaceCoreTest {
    /**
     * Test 1: Stub with matching replacement → emit ReplaceOp.
     */
    @Test
    fun testMatchingReplacement() {
        val stubs = listOf(StubRecord("/Demangler/Foo", "Foo", true))
        val fooReplacement = ReplacementRecord("/proj/Foo", "Foo", emptySet())
        val replacements = mapOf("Foo" to fooReplacement)

        val (ops, skips) = DemanglerReplaceCore.chooseReplaceOps(stubs, replacements)
        assertEquals(1, ops.size, "Should have 1 op")
        assertEquals(0, skips.size, "Should have 0 skips")
        assertEquals("/Demangler/Foo", ops[0].stubPath)
        assertEquals("/proj/Foo", ops[0].replacementPath)
    }

    /**
     * Test 2: Stub without replacement → emit NoReplacement skip.
     */
    @Test
    fun testNoReplacement() {
        val stubs = listOf(StubRecord("/Demangler/Foo", "Foo", true))
        val replacements = emptyMap<String, ReplacementRecord>()

        val (ops, skips) = DemanglerReplaceCore.chooseReplaceOps(stubs, replacements)
        assertEquals(0, ops.size, "Should have 0 ops")
        assertEquals(1, skips.size, "Should have 1 skip")
        assertTrue(skips[0] is Skip.NoReplacement, "Skip should be NoReplacement")
    }

    /**
     * Test 3: Circular dependency (replacement depends on stub) → emit WouldBeCycle skip.
     */
    @Test
    fun testWouldBeCycle() {
        val stubs = listOf(StubRecord("/Demangler/Foo", "Foo", true))
        val fooReplacement =
            ReplacementRecord(
                "/std/Foo",
                "Foo",
                setOf("/Demangler/Foo"),
            )
        val replacements = mapOf("Foo" to fooReplacement)

        val (ops, skips) = DemanglerReplaceCore.chooseReplaceOps(stubs, replacements)
        assertEquals(0, ops.size, "Should have 0 ops")
        assertEquals(1, skips.size, "Should have 1 skip")
        assertTrue(skips[0] is Skip.WouldBeCycle, "Skip should be WouldBeCycle")
    }

    /**
     * Test 4: Non-empty stub → ignored entirely.
     */
    @Test
    fun testNonEmptyStubIgnored() {
        val stubs = listOf(StubRecord("/Demangler/Foo", "Foo", false)) // not empty
        val fooReplacement = ReplacementRecord("/proj/Foo", "Foo", emptySet())
        val replacements = mapOf("Foo" to fooReplacement)

        val (ops, skips) = DemanglerReplaceCore.chooseReplaceOps(stubs, replacements)
        assertEquals(0, ops.size, "Non-empty stub should not produce op")
        assertEquals(0, skips.size, "Non-empty stub should not produce skip")
    }

    /**
     * Test 5: Multiple stubs, mixed outcomes.
     */
    @Test
    fun testMixedOutcomes() {
        val foo = StubRecord("/Demangler/Foo", "Foo", true)
        val bar = StubRecord("/Demangler/Bar", "Bar", true)
        val baz = StubRecord("/Demangler/Baz", "Baz", true)
        val stubs = listOf(foo, bar, baz)

        val fooRepl = ReplacementRecord("/proj/Foo", "Foo", emptySet())
        val bazRepl =
            ReplacementRecord(
                "/proj/Baz",
                "Baz",
                setOf("/Demangler/Baz"),
            )
        val replacements = mapOf("Foo" to fooRepl, "Baz" to bazRepl)

        val (ops, skips) = DemanglerReplaceCore.chooseReplaceOps(stubs, replacements)
        assertEquals(1, ops.size, "Should have 1 op (Foo)")
        assertEquals(2, skips.size, "Should have 2 skips (Bar + Baz)")
        assertTrue(skips.any { it is Skip.NoReplacement }, "Should have NoReplacement skip")
        assertTrue(skips.any { it is Skip.WouldBeCycle }, "Should have WouldBeCycle skip")
    }
}
