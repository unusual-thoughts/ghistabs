package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.ImportOptions.Companion.isStabsDone
import ghistabs.ImportOptions.Companion.markStabsDone
import ghistabs.StabsAnalyzer
import ghistabs.test.must
import ghistabs.test.mustNot
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * The done-flag decides whether [StabsAnalyzer] runs, and it is what stops auto-analysis importing
 * the same stabs a second time on every re-analyze. So the contract is `canAnalyze`, not the
 * option's own round-trip: a program with stabs and no flag is analyzable, the same program with
 * the flag is not, and clearing it again makes it analyzable — which is exactly what a re-import
 * from the Tools menu does.
 */
@Tag("integration")
class StabsAnalyzerLifecycleIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".text", "0x400000", 512)
        builder.createMemory(".stab", "0x401000", 4)
        builder.createMemory(".stabstr", "0x402000", 4)
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun theDoneFlagGatesReanalysis() {
        val program = builder.program
        val analyzer = StabsAnalyzer()

        program.mustNot("a freshly built program has not been imported") { isStabsDone }
        analyzer.must("a program with .stab/.stabstr must be analyzable") { canAnalyze(program) }

        program.markStabsDone(true)
        analyzer.mustNot("the done-flag must keep auto-analysis from re-importing") { canAnalyze(program) }

        program.markStabsDone(false)
        analyzer.must("clearing the flag must re-enable the analyzer") { canAnalyze(program) }
    }

    /** No stab sections, no analyzer — whatever the flag says. */
    @Test
    fun aProgramWithoutStabsIsNeverAnalyzable() {
        val bare = ProgramBuilder("bare", ProgramBuilder._X86)
        try {
            bare.createMemory(".text", "0x400000", 512)
            StabsAnalyzer().mustNot { canAnalyze(bare.program) }
        } finally {
            bare.dispose()
        }
    }
}
