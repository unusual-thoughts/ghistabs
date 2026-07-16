package ghistabs.materialize

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer
import ghistabs.StabsOptions
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.disableWindowsResourceAnalyzer
import ghistabs.importer.ImportContext
import ghistabs.importer.StaticContexts
import ghistabs.runTransaction
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Guards TODO issue 1: `std::string` must materialise as a single filled struct that Ghidra reuses as
 * the `this` type of every `std::string::*` method. Ghidra's GNU demangler expands the `Ss` abbreviation
 * to a `std::string` class and — running AFTER our whole import — creates an empty `/std/string` class
 * struct unless one already sits there. The fix is two-fold and independent of typedef shortening (a
 * render pref): scope-attribution files our type under its namespace category (`/std`), and the canonical
 * key takes the demangler's own leaf spelling (`string`, not `basic_string<char,…>`) as the DTM slot
 * name, so the filled type materialises at exactly `/std/string`; Ghidra's `isNamespaceCategoryMatch`
 * then finds and reuses it — no empty shadow, in either shortening mode.
 *
 * Runs the analyzer in CONCURRENT mode (scheduled alongside full auto-analysis, incl. the demangler) so
 * the demangler's class-struct creation is exercised the same way the GUI triggers it — an AFTER-mode
 * import never sees those symbols demangled. Both shortening modes are checked.
 */
@Tag("integration")
class StringDedupIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun singleStringTypeShorteningOff() = assertSingleStringType(shorten = false)

    @Test
    fun singleStringTypeShorteningOn() = assertSingleStringType(shorten = true)

    private fun assertSingleStringType(shorten: Boolean) {
        val fixture = File("src/test/resources/binaries/xapasmcsr.exe")
        assumeTrue(fixture.exists(), "fixture absent")

        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler("gcc")
            .log(log)
            .monitor(monitor)
            .load()
            .use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                val ctx = ImportContext(
                    program,
                    TaskMonitor.DUMMY,
                    StabsOptions(shortenTypedefs = shorten, minLogLevel = Level.DEBUG),
                    CapturingSink(),
                    StabsDiagnostics(),
                )
                StaticContexts.install(ctx)

                // CONCURRENT: schedule our analyzer for the next pass so it runs at LOW_PRIORITY
                // alongside Ghidra's demangler (which creates the `/std/string` class struct).
                val ourName = StabsAnalyzer().name
                val discovered = mgr.getAnalyzer(ourName)
                Assertions.assertNotNull(discovered, "StabsAnalyzer not discovered by ClassSearcher")
                val options = program.getOptions(Program.ANALYSIS_PROPERTIES)
                program.runTransaction("configure-analysis") {
                    options.setBoolean(ourName, true)
                    // The analyzer reads its own options from the per-analyzer sub-group, not the top level.
                    options.getOptions(ourName).setBoolean(StabsOptions.SHORTEN_TYPEDEFS, shorten)
                }
                mgr.initializeOptions()
                program.disableWindowsResourceAnalyzer()
                mgr.scheduleOneTimeAnalysis(discovered, program.memory)
                mgr.reAnalyzeAll(null)
                program.runTransaction("auto-analyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }

                val dtm = program.dataTypeManager
                // Shortening ON renames the body `basic_string<char,…>` → `string` in place.
                val filledName = "basic_string<char,std::char_traits<char>,std::allocator<char>>"
                val structs = dtm.allDataTypes.asSequence().filterIsInstance<Structure>().toList()

                // (1) Exactly one filled (non-empty) `string`/`basic_string` struct, outside `/Demangler`.
                val bodies = structs
                    .filter { !it.categoryPath.path.startsWith("/Demangler") }
                    .filter { it.name == filledName || it.name == "string" }
                val filled = bodies.filter { it.numComponents > 0 }
                Assertions.assertEquals(
                    1,
                    filled.size,
                    "expected exactly one filled string struct (shorten=$shorten); got " +
                        bodies.joinToString { "${it.pathName}(nc=${it.numComponents})" },
                )

                // (2) No empty `string`-named stub survives — our `/std/string` (named from the demangler
                // leaf via the canonical key) pre-occupies the slot Ghidra's `Ss` class-struct would take,
                // in either shortening mode. Empty structs report length 1 / 0 components.
                val emptyStubs = structs
                    .filter { it.name == "string" && (it.numComponents == 0 || it.isZeroLength) }
                    .map { it.pathName }
                Assertions.assertTrue(
                    emptyStubs.isEmpty(),
                    "empty `string` stub(s) survived the fold (shorten=$shorten): $emptyStubs",
                )

                // (3) `/std/string` — the exact slot Ghidra's this-param creator looks up for `Ss` — is a
                // filled Structure. This is the whole point: our type owns that path so it's reused, not
                // shadowed. (The former `/stabs/string` typedef is now redundant and correctly dropped —
                // the struct itself carries the `string` name.)
                val stdString = dtm.getDataType("/std/string")
                Assertions.assertInstanceOf(
                    Structure::class.java,
                    stdString,
                    "`/std/string` is not a Structure (shorten=$shorten): ${stdString?.pathName}",
                )
                Assertions.assertTrue(
                    (stdString as Structure).numComponents > 0,
                    "`/std/string` is an empty shadow (shorten=$shorten)",
                )
            }
    }
}
