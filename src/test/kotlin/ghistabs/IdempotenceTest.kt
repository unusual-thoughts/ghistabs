package ghistabs

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Integration tests for StabsImporter idempotence.
 *
 * AC6.4: Re-running the importer (with done-flag cleared) on a fully-imported program
 * produces no duplicate types, no duplicate symbols, and byte-identical DTM/symbol state.
 *
 * These tests require real Ghidra Program/DTM objects to verify actual idempotence.
 * See integration tests in src/test/kotlin/ghistabs/integration/ for headless tests.
 */
@Tag("integration")
class IdempotenceTest {
    /**
     * AC6.4 (parsing idempotence): Second run with same input produces identical result counts.
     *
     * Deferred to Kind 2 integration test that uses real Ghidra Program + DTM.
     */
    @Test
    fun testSecondRunProducesSameParseResults() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/ImporterIdempotenceIntegrationTest.kt",
        )
    }

    /**
     * AC6.4 (robustness): Importer handles repeated runs without exceptions.
     *
     * Deferred to Kind 2 integration test that uses real Ghidra Program + DTM.
     */
    @Test
    fun testRepeatedRunsDoNotThrow() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/ImporterIdempotenceIntegrationTest.kt",
        )
    }
}
