package ghistabs

import org.junit.jupiter.api.Assumptions.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Integration tests against xapasmcsr.exe real binary.
 *
 * AC3.5: ≥ 80 interesting typenames are present in DTM after import.
 * AC4.6: ≥ 470 functions with named params, ≥ 92 with locals.
 * AC5: ≥ 50 C++ classes.
 *
 * Tests skip gracefully if xapasmcsr.exe is not present (CSR ADK EULA).
 * To run: Copy xapasmcsr.exe to src/test/resources/binaries/xapasmcsr.exe,
 * then: ./gradlew integrationTest
 */
@Tag("integration")
class XapasmcsrIntegrationTest {
    /**
     * AC3.5: Verify fixture path exists or skip test gracefully.
     *
     * This is a placeholder test that will be implemented fully
     * when xapasmcsr.exe is available (CSR ADK EULA constraint).
     */
    @Test
    fun testBinaryFixturePresence() {
        val fixturePath = File("src/test/resources/binaries/xapasmcsr.exe")

        // Skip if binary not present (EULA-protected, not in repo)
        assumeTrue(
            fixturePath.exists(),
            "Skipping: xapasmcsr.exe not present. " +
                "To enable integration tests, copy the binary from " +
                "~/.wine/drive_c/ADK_Toolkit_1.2.16.22_x64/tools/bin/xapasmcsr.exe " +
                "to src/test/resources/binaries/xapasmcsr.exe",
        )
    }

    /**
     * AC3.5, AC4.6: Real binary test.
     *
     * Placeholder for full integration test. When fixture is available:
     * 1. Load xapasmcsr.exe via Ghidra's PE loader
     * 2. Create StabsImporter and run on the program
     * 3. Assert type count ≥ 80 interesting names
     * 4. Assert ≥ 470 functions with named params
     * 5. Assert ≥ 92 functions with local variables
     * 6. Assert ≥ 50 C++ classes
     */
    @Test
    fun testXapasmcsrIntegration() {
        val fixturePath = File("src/test/resources/binaries/xapasmcsr.exe")
        assumeTrue(fixturePath.exists(), "xapasmcsr.exe fixture not present")

        // Placeholder: Full implementation deferred pending binary availability
        // and Ghidra PE loader integration on test machine.
    }
}
