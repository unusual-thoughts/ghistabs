package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.StabsAnalyzer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Real Ghidra headless integration tests for StabsAnalyzer lifecycle and done-flag management.
 *
 * AC1.3 (first run): After marking done, the done-flag is persisted.
 * AC1.4 (re-import): Clearing the done-flag allows re-analysis.
 *
 * These tests use real Ghidra Program objects with actual option storage,
 * verifying done-flag persistence across transactions.
 */
@Tag("integration")
class StabsAnalyzerLifecycleIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        // Create a minimal test program with x86 architecture
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        // Add memory blocks and stab sections with initialized (zero-filled) memory
        builder.createMemory(".text", "0x400000", 512)
        builder.createMemory(".stab", "0x401000", 4)
        builder.createMemory(".stabstr", "0x402000", 4)
    }

    @AfterEach
    fun tearDown() {
        builder.dispose()
    }

    /**
     * AC1.3 (first run): markStabsDone(true) persists the done-flag.
     *
     * - Create a program
     * - Verify done-flag is initially false
     * - Call markStabsDone(true)
     * - Verify done-flag is true
     * - Verify the state persists after the transaction
     */
    @Test
    fun testFirstRunSetsFlag() {
        val program = builder.program

        // Initially, done-flag should be false
        assertFalse(StabsAnalyzer.isStabsDone(program), "Done-flag should be false initially")

        // Mark as done
        StabsAnalyzer.markStabsDone(program, true)

        // Verify it's now true
        assertTrue(StabsAnalyzer.isStabsDone(program), "Done-flag should be true after marking")

        // Verify program state persists (done by checking the internal option)
        val options = program.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
        assertTrue(
            options.getBoolean(StabsAnalyzer.OPT_STABS_DONE, false),
            "Done-flag should persist in program options",
        )
    }

    /**
     * AC1.4 (re-import): markStabsDone(false) clears the flag to allow re-analysis.
     *
     * - Create a program
     * - Mark done flag as true
     * - Verify it's true
     * - Clear the flag with markStabsDone(false)
     * - Verify it's false again
     * - Verify state persists after the transaction
     */
    @Test
    fun testReimportAfterFlagClear() {
        val program = builder.program

        // First, set the flag to true
        StabsAnalyzer.markStabsDone(program, true)
        assertTrue(StabsAnalyzer.isStabsDone(program), "Done-flag should be true after marking")

        // Now clear the flag to allow re-import
        StabsAnalyzer.markStabsDone(program, false)

        // Verify it's false again
        assertFalse(StabsAnalyzer.isStabsDone(program), "Done-flag should be false after clearing")

        // Verify program state persists
        val options = program.getOptions(ghidra.program.model.listing.Program.PROGRAM_INFO)
        assertFalse(
            options.getBoolean(StabsAnalyzer.OPT_STABS_DONE, true),
            "Done-flag should persist as false in program options after clearing",
        )
    }
}
