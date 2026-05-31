package ghistabs.importer

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ScopePlateDecisionTest {
    @Test
    fun `shouldEmitScopePlate returns false for zero locals`() {
        val result = ScopePlateDecision.shouldEmitScopePlate(0)
        assertFalse(result)
    }

    @Test
    fun `shouldEmitScopePlate returns true for one or more locals`() {
        val result1 = ScopePlateDecision.shouldEmitScopePlate(1)
        assertTrue(result1)

        val result5 = ScopePlateDecision.shouldEmitScopePlate(5)
        assertTrue(result5)
    }
}
