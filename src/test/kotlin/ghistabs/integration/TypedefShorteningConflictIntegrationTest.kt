package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.TypeDef
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportOptions
import ghistabs.importer.ImportOptions.Companion.SHORTEN_TYPEDEFS
import ghistabs.importer.ImportProbe
import ghistabs.importer.STABS_ANALYZER_NAME
import ghistabs.importer.set
import ghistabs.isConflict
import ghistabs.nameWithoutConflict
import ghistabs.runTransaction
import ghistabs.test.disableWindowsResourceAnalyzer
import ghistabs.test.must
import ghistabs.test.mustBeEmpty
import ghistabs.test.mustNotBeNull
import ghistabs.withProgram
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * §21: the import must not fork `/stabs` `.conflict` types, in either shortening mode.
 *
 * The reported case: libstdc++'s stream classes are only cross-referenced, so each is an empty
 * `/stabs` placeholder that the `ostream` / `istream` / … typedefs name. Renaming the placeholder onto
 * the alias folded the typedef away, and the registry's non-resident copy of the pair re-entered the
 * DTM through a later apply as `/stabs/<alias>.conflict`, beside an empty struct wearing the alias.
 *
 * Fixture chosen by measurement, not convenience: of the corpus, only the gcc-3.2/4.2 binaries that
 * take a stream by pointer without defining the class fork at all. `xmltest_gcc421_fullstabs`
 * (TinyXML) forks exactly `/stabs/ostream.conflict` — the reported symptom, minimal, and unencumbered.
 * `crypto_mi_test_gcc421_fullstabs` forks four; `locale_test`, `box2d_tests` and the gcc-3.4.5 builds
 * fork none, so they are not witnesses.
 *
 * Runs CONCURRENT (analyzer scheduled into the analysis session, as the GUI does): with the import run
 * *after* a completed analysis nothing re-applies the stale pair and the bug does not appear — which is
 * also why the CLI cannot reproduce it.
 *
 * Both modes, because typedef *resolution* is unconditional now: `ostream os` resolves to the typedef
 * whether or not shortening is on, so the off case is no longer the trivially-empty configuration.
 */
@Tag("integration")
class TypedefShorteningConflictIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun forksNoConflictsShorteningOn() = assertNoStabsConflicts(shorten = true)

    @Test
    fun forksNoConflictsShorteningOff() = assertNoStabsConflicts(shorten = false)

    private fun assertNoStabsConflicts(shorten: Boolean) {
        val fixture = Fixtures.orDefault(DEFAULT_FIXTURE)
        val monitor = TaskMonitor.DUMMY
        withProgram(fixture, log = MessageLog(), monitor = monitor) { program ->
            val ctx = ImportContext(
                program,
                monitor,
                ImportOptions(shortenTypedefs = shorten, minLogLevel = Level.DEBUG),
                CapturingSink(),
                StabsDiagnostics(),
            )
            val probe = ImportProbe.install(ctx)
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            val discovered = mgr.getAnalyzer(STABS_ANALYZER_NAME)
            discovered.mustNotBeNull("StabsAnalyzer not discovered by ClassSearcher")
            val options = program.getOptions(Program.ANALYSIS_PROPERTIES)
            program.runTransaction("configure-analysis") {
                options.setBoolean(STABS_ANALYZER_NAME, true)
                options.getOptions(STABS_ANALYZER_NAME)[SHORTEN_TYPEDEFS] = shorten
            }
            mgr.initializeOptions()
            program.disableWindowsResourceAnalyzer()
            mgr.scheduleOneTimeAnalysis(discovered, program.memory)
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            }

            // Alias names come from the *stabs declarations*, not the DTM: before the fix the DTM had no
            // `ostream` typedef left to read them off — the rename had folded it away — so a DTM-derived
            // set would make this check vacuous exactly when it matters.
            val aliases = checkNotNull(probe.artifacts) { "artifacts not populated" }
                .types.namedPrimitiveTypedefs.keys
            val stabs = program.dataTypeManager.allDataTypes.asSequence()
                .filter { it.categoryPath.path == "/stabs" }.toList()
            // Only forks on a typedef *alias* are this bug. A fork on the target's own name
            // (`basic_ostream<…>.conflict`) is the separate, still-unowned §21 drift — present on this
            // fixture in both modes and on both sides of the fix, so folding it in here would just
            // make the test unfixable noise.
            stabs.filter { it.isConflict() && it.nameWithoutConflict in aliases }
                .map { d ->
                    "${d.pathName} [${d.javaClass.simpleName}]" +
                        (d as? TypeDef)?.let { " -> ${it.dataType.pathName}" }.orEmpty()
                }
                .sorted()
                .mustBeEmpty("import forked a `/stabs` conflict on a typedef alias (shortenTypedefs=$shorten)")
            // `ostream` stays a typedef onto its (empty, fillable) target in both modes: resolution
            // hands references the typedef rather than renaming anything, and the rename half only
            // rewrites template *arguments*, never a whole name a typedef already carries.
            stabs.single { it.name == "ostream" }
                .must("/stabs/ostream should stay a typedef onto its target") { this is TypeDef }
        }
    }

    companion object {
        const val DEFAULT_FIXTURE = "xmltest_gcc421_fullstabs.exe"
    }
}
