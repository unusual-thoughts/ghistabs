package ghistabs

import ghidra.program.model.listing.Program
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

/**
 * Tests for StabsAnalyzer lifecycle: done-flag management.
 *
 * AC1.3 (first run): After marking done, the done-flag is persisted.
 * AC1.4 (re-import): Clearing the done-flag allows re-analysis.
 * AC1.5 (no-stabs): Tested with integration tests on real binaries via bouniafbouniafIntegrationTest.
 * AC1.3 (idempotence): Tested via IdempotenceTest which verifies parsing is consistent across runs.
 *
 * Note: Full canAnalyze logic testing with memory blocks is complex to mock across Ghidra versions.
 * It is covered by integration tests (bouniafbouniafIntegrationTest) which use real binaries.
 */
class StabsAnalyzerLifecycleTest {
    /**
     * AC1.3 (first run): markStabsDone(true) calls setBoolean on PROGRAM_INFO options.
     */
    @Test
    fun testFirstRunSetsFlag() {
        val (program, programInfoOptions) = buildMockProgram()

        // Mark as done
        StabsAnalyzer.markStabsDone(program, true)

        // Verify that setBoolean was called with the done-flag key on PROGRAM_INFO options
        verify(programInfoOptions).setBoolean(StabsAnalyzer.STABS_DONE_OPTION, true)
    }

    /**
     * AC1.4 (re-import): markStabsDone(false) clears the flag.
     */
    @Test
    fun testReimportAfterFlagClear() {
        val (program, programInfoOptions) = buildMockProgram()

        // Mark as done
        StabsAnalyzer.markStabsDone(program, true)
        // Then clear
        StabsAnalyzer.markStabsDone(program, false)

        // Verify that setBoolean was called twice
        verify(programInfoOptions).setBoolean(StabsAnalyzer.STABS_DONE_OPTION, true)
        verify(programInfoOptions).setBoolean(StabsAnalyzer.STABS_DONE_OPTION, false)
    }

    /**
     * Helper: Build a mock Program for testing flag management.
     * Returns a Pair of (Program, PROGRAM_INFO options) for verification.
     */
    private fun buildMockProgram(): Pair<Program, ghidra.framework.options.Options> {
        val program = mock<Program>()
        val programInfoOptions = mock<ghidra.framework.options.Options>()

        whenever(program.getOptions(Program.PROGRAM_INFO)).thenReturn(programInfoOptions)

        // Setup transaction methods
        whenever(program.startTransaction(any())).thenReturn(1)
        whenever(program.endTransaction(any<Int>(), any<Boolean>())).thenReturn(true)

        return Pair(program, programInfoOptions)
    }
}
