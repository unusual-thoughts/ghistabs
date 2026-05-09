package ghistabs

import org.junit.jupiter.api.Assumptions.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Integration tests against bouniafbouniaf.exe real binary.
 *
 * AC3.5: ≥ 80 interesting typenames are present in DTM after import.
 * AC4.6: ≥ 470 functions with named params, ≥ 92 with locals.
 * AC5: ≥ 50 C++ classes.
 *
 * Tests skip gracefully if bouniafbouniaf.exe is not present (bouniaf bouniaf bouniaf).
 * To run: Copy bouniafbouniaf.exe to src/test/resources/binaries/bouniafbouniaf.exe,
 * then: ./gradlew integrationTest
 */
@Tag("integration")
class bouniafbouniafIntegrationTest {
    /**
     * AC3.5: Verify fixture path exists or skip test gracefully.
     *
     * This is a placeholder test that will be implemented fully
     * when bouniafbouniaf.exe is available (bouniaf bouniaf bouniaf constraint).
     */
    @Test
    fun testBinaryFixturePresence() {
        val fixturePath = File("src/test/resources/binaries/bouniafbouniaf.exe")

        // Skip if binary not present (bouniaf-protected, not in repo)
        assumeTrue(
            fixturePath.exists(),
            "Skipping: bouniafbouniaf.exe not present. " +
                "To enable integration tests, copy the binary from " +
                "~/.wine/drive_c/bouniaf_bouniaf_x64/tools/bin/bouniafbouniaf.exe " +
                "to src/test/resources/binaries/bouniafbouniaf.exe",
        )
    }

    /**
     * AC3.5, AC4.6: Real binary test.
     *
     * Placeholder for full integration test. When fixture is available:
     * 1. Load bouniafbouniaf.exe via Ghidra's PE loader
     * 2. Create StabsImporter and run on the program
     * 3. Assert type count ≥ 80 interesting names
     * 4. Assert ≥ 470 functions with named params
     * 5. Assert ≥ 92 functions with local variables
     * 6. Assert ≥ 50 C++ classes
     */
    @Test
    fun testbouniafbouniafIntegration() {
        val fixturePath = File("src/test/resources/binaries/bouniafbouniaf.exe")
        assumeTrue(fixturePath.exists(), "bouniafbouniaf.exe fixture not present")

        // Placeholder: Full implementation deferred pending binary availability
        // and Ghidra PE loader integration on test machine.
    }
}
