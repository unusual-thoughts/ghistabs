package ghistabs.builder

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Integration tests for TypeRegistry data type materialization.
 *
 * AC3.1: Cross-compilation-unit struct deduplication works.
 * AC3.2: Conflict naming for same-named structs with different bodies.
 * AC3.3: Attribution (category path assignment) is correct.
 * AC3.4: Self-reference and mutual cycles handled correctly.
 *
 * These tests require real Ghidra DataTypeManager to verify actual type deduplication
 * and conflict handling. See integration tests in src/test/kotlin/ghistabs/integration/
 * for headless tests.
 */
@Tag("integration")
class TypeRegistryTest {
    /**
     * AC3.1: Cross-compilation unit struct deduplication.
     * Deferred to Kind 2 integration test with real DataTypeManager.
     */
    @Test
    fun testCrossUDedup() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/TypeRegistryIntegrationTest.kt",
        )
    }

    /**
     * AC3.2: Conflict naming for same-named structs with different bodies.
     * Deferred to Kind 2 integration test with real DataTypeManager.
     */
    @Test
    fun testConflictNaming() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/TypeRegistryIntegrationTest.kt",
        )
    }

    /**
     * AC3.3: Attribution (category path assignment).
     * Deferred to Kind 2 integration test with real DataTypeManager.
     */
    @Test
    fun testAttribution() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/TypeRegistryIntegrationTest.kt",
        )
    }

    /**
     * AC3.4: Self-pointer cycles.
     * Deferred to Kind 2 integration test with real DataTypeManager.
     */
    @Test
    fun testSelfPointerCycle() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/TypeRegistryIntegrationTest.kt",
        )
    }

    /**
     * AC3.4: Mutual pointer cycles.
     * Deferred to Kind 2 integration test with real DataTypeManager.
     */
    @Test
    fun testMutualCycle() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/TypeRegistryIntegrationTest.kt",
        )
    }
}
