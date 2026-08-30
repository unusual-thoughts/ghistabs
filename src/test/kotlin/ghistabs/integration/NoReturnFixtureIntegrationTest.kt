package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * [ghistabs.NoReturnAnalyzer] against one real binary, through the ordinary analyzer pipeline.
 *
 * **One configuration per invocation**, because each is a full load + autoanalysis. Both write
 * `build/test-output/noreturn/<fixture>.<on|off>.txt`, and `diff`ing the two files *is* the with/
 * without comparison — no run has to pay for both:
 *
 * - `-PdisableAnalyzers=reachability` — the **before** roster. Ghidra's own marks alone; this
 *   analyzer never runs, by the pipeline or by hand.
 * - no flag — the **after** roster. Additionally asserts the analyzer is picked up automatically
 *   (nothing here schedules it) and that running it again separately finds nothing more.
 *
 * The gate is from `docs/notes/render-backlog.md` §31 and both halves matter. The reverted first
 * attempt got `error()` and 31 libstdc++ false positives with it; the conservative repair of that got
 * zero wrong and also lost `error()`, which was the whole point.
 */
@Tag("integration")
class NoReturnFixtureIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun nonReturningRoster() {
        val fixture = Fixtures.singleFile
        val binary = fixture.name

        withAnalyzed(fixture) { program, disabled ->
            // Derived from what was actually disabled, not from the flag text, so a typo'd
            // `-PdisableAnalyzers` cannot mislabel an on-run as the baseline.
            val on = NO_RETURN_ANALYZER_NAME !in disabled
            val marked = program.functionManager.functionsIterable.filter { it.hasNoReturn() }

            File("build/test-output/noreturn").apply { mkdirs() }
                .resolve("$binary.${if (on) "on" else "off"}.txt")
                // Terminator per entry, not a separator plus postfix: an empty roster is a legitimate
                // result (the a.out `.o` fixtures) and must be an empty file, not one blank line.
                .writeText(
                    marked.sortedBy { it.entryPoint }.joinToString("") {
                        "${it.entryPoint} ${it.getName(true)}\n"
                    },
                )
            println("noreturn: $binary analyzer=${if (on) "on" else "off"} marked=${marked.size}")

            // Liveness, not a result: zero is *correct* for the unlinked a.out `.o` fixtures, which
            // have no libc linked and so nothing known non-returning to anchor a walk.
            program.functionManager.must("no functions at all — did analysis run?") { functionCount > 0 }

            // libstdc++'s locale and iostream functions are switch-table-heavy, which is what the
            // reverted instruction walk mistook for proof that they cannot return.
            marked.filter(::isLibraryCxx).map { "${it.entryPoint} ${it.name}" } mustBe emptyList<String>()

            if (!on) return@withAnalyzed // the baseline roster is the whole product of an off run

            // Nothing schedules this analyzer explicitly, so a broken priority or a `canAnalyze`
            // regression would leave every other assertion here passing over Ghidra's own marks.
            val discovered = AutoAnalysisManager.getAnalysisManager(program).getAnalyzer(NO_RETURN_ANALYZER_NAME)
            discovered.mustBeA<NoReturnAnalyzer>("ClassSearcher did not pick up $NO_RETURN_ANALYZER_NAME")

            // Running it again, separately, must find nothing the automatic pass missed — the fixed
            // point has to be order-independent, and re-running has to stay cheap and idempotent.
            val again = program.runTransaction(NO_RETURN_ANALYZER_NAME) {
                markNoReturn(program, program.memory.loadedAndInitializedAddressSet)
            }
            again.map(Function::getName).mustBeEmpty("a second pass found more")

            // A conservative rule that fires on nothing is no use either.
            MUST_BE_MARKED[binary].orEmpty().forEach { want ->
                marked.must("$want must be marked non-returning") { any { it.name == want } }
            }
        }
    }

    /** Loads [fixture] and runs full autoanalysis, returning the analyzers `-PdisableAnalyzers` turned off. */
    private fun withAnalyzed(fixture: File, check: (Program, List<String>) -> Unit) =
        withProgram(fixture, log = MessageLog(), monitor = TaskMonitor.DUMMY) { program ->
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            program.disableWindowsResourceAnalyzer()
            val disabled = program.disableAnalyzersFromProperty()
            // A load alone queues nothing; without this startAnalysis returns instantly.
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(TaskMonitor.DUMMY)
                mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
            }
            check(program, disabled)
        }

    /**
     * A libstdc++ function outside the throw/terminate machinery. That machinery really does never
     * return — `std::__throw_length_error`, `std::terminate`, `__cxa_throw` — so the gate has to admit
     * it, and every one of the 31 false positives (`strtold`, `do_put`, `_S_pad`, `_M_widen_float`, …)
     * sits outside it.
     *
     * Deliberately narrow, and therefore blind outside libstdc++: cryptopp's `CryptoPP::` base-class
     * stubs (`Clonable::Clone`, `CryptoMaterial::Save`, `InputRejecting<T>::Put2`, …) all throw
     * `NotImplemented` and are correctly marked, but nothing here would catch a *wrong* mark in that
     * namespace. The written roster is the artifact for that; this asserts only the known regression.
     */
    private fun isLibraryCxx(f: Function) = (
        generateSequence(f.parentNamespace) { it.parentNamespace }.any { it.name in LIBRARY_NAMESPACES } ||
            LIBRARY_MANGLINGS.any(f.name::startsWith)
        ) &&
        NEVER_RETURNS_BY_DESIGN.none { it in f.getName(true) }

    private companion object {
        val LIBRARY_NAMESPACES = setOf("std", "__gnu_cxx", "__cxxabiv1")
        val LIBRARY_MANGLINGS = listOf("_ZSt", "_ZNSt", "_ZNKSt", "_ZN9__gnu_cxx", "_ZNK9__gnu_cxx")
        val NEVER_RETURNS_BY_DESIGN = listOf("__throw", "terminate", "unexpected", "__cxa", "_Unwind")

        /**
         * Per fixture, the functions the analyzer exists to find — each verified in the disassembly,
         * and each outside Ghidra's own known-function marks, so a pass here is the walk working
         * rather than the loader's list. `__assert` is mingw's assert helper, which prints and falls
         * into `abort`; `BERDecodeError` is a constructor that only throws.
         */
        val MUST_BE_MARKED = mapOf(
            "crypto_mi_test_gcc421.exe" to listOf("__assert", "BERDecodeError"),
        )
    }
}
