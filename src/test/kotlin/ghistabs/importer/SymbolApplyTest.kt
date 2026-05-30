package ghistabs.importer

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Integration tests for symbol applying during import.
 *
 * AC4.3: Global variable stab harvesting and address resolution works.
 * AC6.2: Importer continues past malformed records.
 *
 * These tests require real Ghidra Program/Listing objects to verify symbol creation.
 * See integration tests in src/test/kotlin/ghistabs/integration/ for headless tests.
 */
@Tag("integration")
class SymbolApplyTest {
    /**
     * AC4.3: Global variable - stab harvesting and address resolution works.
     *
     * Deferred to Kind 2 integration test that uses real Ghidra Program.
     */
    @Test
    fun testGlobalSymbolHarvesting() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/SymbolApplyIntegrationTest.kt",
        )
    }

    /**
     * AC6.2: Importer continues past malformed record.
     *
     * Deferred to Kind 2 integration test that uses real Ghidra Program.
     */
    @Test
    fun testContinuesOnParseError() {
        assumeTrue(
            false,
            "Deferred to Kind 2 integration test. " +
                "See integration/SymbolApplyIntegrationTest.kt",
        )
    }
}
