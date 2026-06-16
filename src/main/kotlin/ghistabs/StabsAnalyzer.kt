package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer.Companion.OPT_STABS_DONE
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.diagnose.TeeSink
import ghistabs.diagnose.toSink
import ghistabs.importer.ImportContext
import ghistabs.importer.StabsImporter
import ghistabs.importer.StaticContexts

/**
 * Imports STABS debug info (.stab/.stabstr) into Ghidra: types, function signatures,
 * locals, C++ classes, vtables. Targets PE/ELF binaries produced by Cygwin gcc 3.4.4.
 *
 * Auto-runs once per program (gated by [OPT_STABS_DONE]); re-runnable via the
 * `Tools > Stabs > Re-import` menu action.
 */
class StabsAnalyzer :
    AbstractAnalyzer(
        "Stabs Importer",
        "Imports STABS debug info (.stab/.stabstr) — types, function signatures, locals, C++ classes, vtables.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // Run AFTER Ghidra's demangler (priority ~897, i.e.
        // DATA_TYPE_PROPOGATION.before().before().before()). If we ran earlier
        // we'd promote function symbols to IMPORTED ahead of the demangler,
        // which then skips them and leaves names mangled in the listing.
        // LOW_PRIORITY (10000) keeps us strictly after every standard analyzer.
        priority = AnalysisPriority.LOW_PRIORITY
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun getDefaultEnablement(program: Program?): Boolean = true

    override fun canAnalyze(program: Program?): Boolean {
        if (program == null) return false
        if (isStabsDone(program)) return false
        val mem = program.memory
        return mem.getBlock(".stab") != null && mem.getBlock(".stabstr") != null
    }

    override fun registerOptions(options: Options, program: Program?) {
        options.registerOption(
            OPT_PLATE_COMMENTS,
            true,
            null,
            "Apply plate comments at lexical scopes when LBRAC/RBRAC info is present.",
        )
        options.registerOption(
            OPT_VTABLES,
            true,
            null,
            "Synthesise <Class>_vtable structs and apply at _ZTV addresses.",
        )
    }

    fun run(ctx: ImportContext<*>) {
        if (isStabsDone(ctx.program)) return // idempotent re-trigger; treat as success.

        val result = StabsImporter(ctx).run()
        ctx.sink.log("done", "import complete: $result")
        markStabsDone(ctx.program, true)
    }

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        log ?: return false
        monitor ?: return false
        val msgSink = log.toSink()
        val ext = StaticContexts.get(program)
        run(
            ImportContext(
                program,
                monitor,
                options = StabsOptions(program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(name)),
                // Tee onto ext.log (the raw CapturingSink), NOT ext.sink: the latter
                // is a BookmarkSink that auto-bumps `ext.diagnostics` on every log()
                // call. Since we already share `ext.diagnostics` via the explicit
                // `diagnostics =` arg below, our own BookmarkSink would inc once and
                // the tee'd ext.sink would inc again — every counter would double.
                log = ext?.let { TeeSink(msgSink, it.log) } ?: msgSink,
                diagnostics = ext?.diagnostics ?: StabsDiagnostics(),
            ),
        )
        return true
    }

    companion object {
        const val OPT_STABS_DONE: String = "Stabs Imported"
        const val OPT_PLATE_COMMENTS: String = "Apply scope plate comments"
        const val OPT_VTABLES: String = "Synthesise vtable structs"

        @JvmStatic
        fun isStabsDone(program: Program) = program.getOptions(Program.PROGRAM_INFO).getBoolean(OPT_STABS_DONE, false)

        @JvmStatic
        fun markStabsDone(program: Program, value: Boolean) {
            val tx = program.startTransaction("Stabs: set done flag")
            try {
                program.getOptions(Program.PROGRAM_INFO).setBoolean(OPT_STABS_DONE, value)
            } finally {
                program.endTransaction(tx, true)
            }
        }
    }
}

data class StabsOptions(
    val createImportedLabels: Boolean = true,
    val applyPlateComments: Boolean = true,
    val applyVtables: Boolean = true,
) {
    constructor(opts: Options) : this(
        applyPlateComments = opts.getBoolean(StabsAnalyzer.OPT_PLATE_COMMENTS, true),
        applyVtables = opts.getBoolean(StabsAnalyzer.OPT_VTABLES, true),
    )
}
