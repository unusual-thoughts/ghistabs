package ghicpp.analyzers

import ghicpp.ClassRecordSource
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.integration.FeatureFixtureTest
import ghistabs.loadProgram
import ghistabs.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * The Itanium class analyzer leaves a binary with stabs to them, told through a [ClassRecordSource] found by
 * Ghidra's ClassSearcher rather than by asking the stabs stages.
 */
@Tag("integration")
class ItaniumClassAnalyzerStabsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private fun analyzes(fixture: String): Pair<Boolean, Boolean> =
        loadProgram(File(FeatureFixtureTest.FEATURES, fixture), "gcc").use {
            ClassRecordSource.describedElsewhere(it.program) to ItaniumClassAnalyzer().canAnalyze(it.program)
        }

    @Test
    fun `a binary with stabs is described by the stabs, so the analyzer skips it`() {
        analyzes("hello_elf_gcc12") mustBe (true to false)
    }

    @Test
    fun `a stripped binary has no other source, so the analyzer runs`() {
        analyzes("hello_elf_gcc12_stripped") mustBe (false to true)
    }
}
