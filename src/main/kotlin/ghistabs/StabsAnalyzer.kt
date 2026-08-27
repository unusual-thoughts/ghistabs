package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions.Companion.isOverlayDone
import ghistabs.ImportOptions.Companion.isStabsDone
import ghistabs.ImportOptions.Companion.markOverlayDone
import ghistabs.ImportOptions.Companion.markStabsDone
import ghistabs.ImportOptions.Companion.registerStabs
import ghistabs.diagnose.BookmarkSink
import ghistabs.diagnose.MessageLogSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.diagnose.TeeSink
import ghistabs.importer.*
import ghistabs.parse.StabReader

/**
 * Imports STABS debug info (.stab/.stabstr) into Ghidra: types, function signatures,
 * locals, C++ classes, vtables. Covers gcc 3.2 through 12 — 13 dropped stabs emission — on both
 * Unix and Cygwin targets, across ELF, PE/COFF and a.out (where the records live in the linker
 * symbol table rather than in debug sections).
 *
 * Auto-runs once per program (gated by [ImportOptions.STABS_DONE]); re-runnable via the
 * `Tools > Stabs > Re-import` menu action.
 */
class StabsAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Imports STABS debug info (.stab/.stabstr) — types, function signatures, locals, C++ classes, vtables.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // Must run AFTER Ghidra's demangler (~897). Earlier and we promote function symbols to
        // IMPORTED before the demangler runs — it then skips them, leaving names mangled.
        priority = AnalysisPriority.LOW_PRIORITY
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun getDefaultEnablement(program: Program?): Boolean = true

    override fun canAnalyze(program: Program?): Boolean {
        if (program == null) return false
        if (program.isStabsDone) return false
        return StabReader.hasStabs(program)
    }

    override fun registerOptions(options: Options, program: Program?) = options.registerStabs()

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, msg: MessageLog?): Boolean {
        program ?: return false
        msg ?: return false
        monitor ?: return false
        val options = ImportOptions(program)
        val probe = ImportProbe.get(program)

        val ctx = ImportContext(
            program,
            monitor,
            options,
            // Bookmark every addressed diagnostic (unconditional); MessageLog gets output at/above minLevel.
            // Tee the emitting terminal onto the probe's raw CapturingSink so tests can inspect output;
            // counting is the shared probe.diagnostics accumulator, tee'd in ImportContext.
            terminal = TeeSink(BookmarkSink(program), MessageLogSink(msg, options.minLogLevel), probe?.terminal),
            diagnostics = probe?.diagnostics ?: StabsDiagnostics(),
        )
        // A test installed `probe` to read what the analyzer built (registry dump, DemanglerReplacer);
        // hand back the materialized artifacts. Null on a re-fired pass (import short-circuits on
        // isStabsDone) — don't clobber. No-op in production (probe == null).
        ctx.import().artifacts?.let { probe?.artifacts = it }

        return true
    }

    companion object {
        const val NAME = "Stabs Importer"

        @JvmStatic
        fun ImportContext<*>.import(): ImportResult {
            if (program.isStabsDone) return ImportResult()

            if (options.overlaySection && !program.isOverlayDone) {
                debug("stab-section-overlaid", count = StabSectionOverlay(this).apply().toLong())
                program.markOverlayDone()
            }

            val results = StabsImporter(this).run()
            log("import", "import complete: $results")
            program.markStabsDone(true)
            return results
        }
    }
}
