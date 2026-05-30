package ghistabs

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Integration tests for StabsAnalyzer lifecycle: done-flag management.
 *
 * AC1.3 (first run): After marking done, the done-flag is persisted.
 * AC1.4 (re-import): Clearing the done-flag allows re-analysis.
 * AC1.5 (no-stabs): Tested with integration tests on real binaries via bouniafbouniafIntegrationTest.
 *
 * These tests require real Ghidra Program objects with actual option storage.
 * See integration tests in src/test/kotlin/ghistabs/integration/ for headless tests.
 */
@Tag("integration")
class StabsAnalyzerLifecycleTest {
    /**
     * AC1.3 (first run): markStabsDone(true) persists done-flag.
     * Deferred to Kind 2 integration test with real Program.
     */
    @Test
    fun testFirstRunSetsFlag() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/StabsAnalyzerLifecycleIntegrationTest.kt",
        )
    }

    /**
     * AC1.4 (re-import): markStabsDone(false) clears the flag.
     * Deferred to Kind 2 integration test with real Program.
     */
    @Test
    fun testReimportAfterFlagClear() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/StabsAnalyzerLifecycleIntegrationTest.kt",
        )
    }
}
