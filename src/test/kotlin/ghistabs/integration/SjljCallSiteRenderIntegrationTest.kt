package ghistabs.integration

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.LoadedProgram
import ghistabs.cpp.eh.SjljApplier
import ghistabs.functionsIterable
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportOptions.Companion.disableStabsAnalyzer
import ghistabs.loadProgram
import ghistabs.render.Renderer
import ghistabs.render.Renderer.Mode
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.io.File

/**
 * Every SJLJ call-site comment the decompiler prints for a function reaches that function's render.
 *
 * `crypto_mi_test_gcc345`'s libstdc++ is optimized, so `functexcept.cc`'s `__throw_logic_error(__s)`
 * and its siblings inline the `std::string(__s)` they throw with, and gcc schedules the
 * `fc.call_site = N` stores among the inlined instructions: their N_SLINEs name `basic_string.h` or
 * `new_allocator.h`. The render drops inlined statements from the caller's view, and the store went
 * with them, comment and all. Each function kept only call site 4, the one before the inlined code
 * starts, and lost 3 and 1.
 */
@Tag("integration")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SjljCallSiteRenderIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private lateinit var artifacts: ImportArtifacts
    private val program: Program get() = loaded.program

    @BeforeAll
    fun setUp() {
        val fixture = File("src/test/resources/binaries/$FIXTURE")
        assumeTrue(Fixtures.accepts(FIXTURE), "excluded by -Pfixture")
        // As the AFTER-mode matrix loads it, so a run after the matrix restores its analysis.
        loaded = AnalysisCache.restore(fixture, this) ?: loadProgram(fixture).also { analyze(fixture, it.program) }
        artifacts = program.runTransaction("stabs-analyze") {
            checkNotNull(program.defaultContext().importAndAnalyze().artifacts) { "$FIXTURE carries no stabs" }
        }
    }

    private fun analyze(fixture: File, program: Program) {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        program.disableStabsAnalyzer()
        mgr.initializeOptions()
        program.disableWindowsResourceAnalyzer()
        mgr.reAnalyzeAll(null)
        program.runTransaction("auto-analyze") {
            mgr.startAnalysis(TaskMonitor.DUMMY)
            mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
        }
        AnalysisCache.store(fixture, program)
    }

    @AfterAll
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    /** The call-site comments in the decompiler's own C for each `std::__throw_*`, by text. */
    private fun decompiled(): Map<String, Int> {
        val decomp = DecompInterface()
        decomp.openProgram(program)
        try {
            return program.functionManager.functionsIterable
                .filter { it.name.startsWith("__throw_") && it.parentNamespace.name == "std" }
                .flatMap { f ->
                    decomp.decompileFunction(f, 60, TaskMonitor.DUMMY).decompiledFunction.c.callSiteComments()
                }
                .groupingBy { it }.eachCount()
        } finally {
            decomp.dispose()
        }
    }

    private fun String.callSiteComments() =
        Regex("""/\* (${SjljApplier.CALL_SITE_PREFIX} [^*]*) \*/""").findAll(this).map { it.groupValues[1] }.toList()

    @ParameterizedTest
    @EnumSource(Mode::class, names = ["DECOMPILE", "ELIDE_SJLJ"])
    fun `a call site gcc scheduled into inlined code keeps its comment`(mode: Mode) {
        val expected = decompiled()
        expected.mustNotBeEmpty("no std::__throw_* prints a call-site comment, so nothing below asserts anything")
        val text = Renderer(mode, program.defaultContext(), artifacts.hints).use { r ->
            val source = r.sources.single { it.filename == "functexcept.cc" }
            program.runTransaction("render") { r.renderSkeleton(source) }
        }
        text.callSiteComments().groupingBy { it }.eachCount() mustBe expected
        if (mode == Mode.DECOMPILE) {
            text.must("the store under its comment") { "fc.call_site = 3;" in this && "fc.call_site = 1;" in this }
        }
    }

    private companion object {
        const val FIXTURE = "crypto_mi_test_gcc345.exe"
    }
}
