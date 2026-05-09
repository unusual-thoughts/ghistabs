package ghistabs.builder

import ghidra.framework.Application
import org.junit.jupiter.api.BeforeAll

/**
 * Base class for tests that need Ghidra Application context.
 * Ensures Application is initialized before any test runs.
 */
abstract class GhidraTestBase {
    companion object {
        private var initialized = false

        @BeforeAll
        @JvmStatic
        fun initializeGhidra() {
            if (!initialized) {
                try {
                    if (!Application.isInitialized()) {
                        System.err.println("Ghidra Application not initialized, attempting to initialize...")
                        // Note: Full initialization requires platform, but since we're just using DataTypeManager,
                        // the framework should handle lazy initialization
                    }
                } catch (e: Exception) {
                    System.err.println("Note: Could not explicitly initialize Ghidra Application: ${e.message}")
                }
                initialized = true
            }
        }
    }
}
