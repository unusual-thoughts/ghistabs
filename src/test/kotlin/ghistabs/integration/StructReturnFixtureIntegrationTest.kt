package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.Correction
import ghistabs.functionsIterable
import ghistabs.runTransaction
import ghistabs.test.*
import ghistabs.withProgram
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertAll

/**
 * [ghistabs.StructReturnAnalyzer] against a real gcc 3.4.5 PE, through the ordinary analyzer pipeline — the
 * Stabs Importer supplies the return types this reads, so the priority ordering is exercised for
 * real rather than simulated.
 *
 * The assertions are invariants, not a roster of expected functions: libstdc++ template spellings are
 * far too brittle to pin, and the invariant *is* the analyzer's contract — a derived convention must
 * always agree with the callee's stack purge, and `this` must land after any hidden return slot.
 * Nothing may be corrected where purge and the cspec already agree, which is the `FileSystemImage::root`
 * regression that motivated the purge check.
 *
 * `locale_test`, and it exercises both directions:
 * `std::locale::global` / `collate<char>::transform` return a non-trivial 4-byte class through memory,
 * while `num_get::_M_extract_int` returns a trivial 4-byte iterator in EAX.
 */
@Tag("integration")
class StructReturnFixtureIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun localeTestStructReturns() = withAnalyzed { program ->
        val corrected = program.functionManager.functionsIterable
            .filter { f -> Correction.entries.any { f.callingConventionName.endsWith(it.suffix) } }
        val (toMemory, toRegister) = corrected.partition {
            it.callingConventionName.endsWith(Correction.TO_MEMORY.suffix)
        }
        val pointer = program.defaultPointerSize

        assertAll(
            { toMemory.mustNotBeEmpty("expected non-trivial small class returns to be corrected to sret") },
            { toRegister.mustNotBeEmpty("expected trivial POD returns to be corrected to register") },
            // Every correction is justified by the epilogue, in the direction it claims.
            { toMemory.forEach { it.stackPurgeSize.mustBe(pointer, "${it.name} @ ${it.entryPoint} purge") } },
            { toRegister.forEach { it.stackPurgeSize.mustBe(0, "${it.name} @ ${it.entryPoint} purge") } },
            { toMemory.forEach { it.`return`.must("${it.name} must return indirect") { isForcedIndirect } } },
            { toRegister.forEach { it.`return`.mustNot("${it.name} must return in registers") { isForcedIndirect } } },
            { toMemory.forEach { it.must("${it.name} needs the hidden pointer") { hasReturnStoragePtr() } } },
            { toRegister.forEach { it.mustNot("${it.name} must drop the hidden pointer") { hasReturnStoragePtr() } } },
            { corrected.forEach { assertThisOffset(it, pointer) } },
            // Storage comes from the convention, never frozen onto the function.
            { corrected.forEach { it.mustNot("${it.name} has custom storage") { hasCustomVariableStorage() } } },
        )
    }

    /** `this` sits one pointer past the hidden return slot when there is one, at the base offset otherwise. */
    private fun assertThisOffset(f: Function, pointer: Int) {
        val self = f.parameters.firstOrNull { it.name == "this" } ?: return
        if (!self.variableStorage.isStackStorage) return
        val expected = pointer + if (f.hasReturnStoragePtr()) pointer else 0
        self.variableStorage.stackOffset.mustBe(expected, "${f.name} @ ${f.entryPoint}: `this` offset")
    }

    private fun Function.hasReturnStoragePtr() = parameters.any { it.name == "__return_storage_ptr__" }

    private fun withAnalyzed(check: (Program) -> Unit) {
        val fixture = Fixtures.orDefault(DEFAULT_FIXTURE)
        withProgram(fixture, log = MessageLog(), monitor = TaskMonitor.DUMMY) { program ->
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            program.disableWindowsResourceAnalyzer()
            // Without this nothing is queued and startAnalysis returns immediately: a load alone
            // does not schedule the FUNCTION_ANALYZER pass this depends on.
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(TaskMonitor.DUMMY)
                mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
            }
            check(program)
        }
    }

    private companion object {
        /** Any libstdc++-linked gcc 3.4.5 PE exercises both directions; `-Pfixture` redirects it. */
        const val DEFAULT_FIXTURE = "locale_test_gcc345_fullstabs.exe"
    }
}
