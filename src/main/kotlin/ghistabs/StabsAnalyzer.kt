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
import ghistabs.diagnose.Level
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
        // Must run AFTER Ghidra's demangler (~897). Earlier and we promote function symbols to
        // IMPORTED before the demangler runs — it then skips them, leaving names mangled.
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
        options.registerOption(
            OPT_LOG_DEGRADATIONS,
            false,
            null,
            "Dump every materialization degradation (Undefined4 fallback, synthesised base, " +
                "skipped field, dropped vtable slot, …) at end-of-run.",
        )
        options.registerOption(
            OPT_SHORTEN_TYPEDEFS,
            false,
            null,
            "Rename long templated datatypes onto their shorter typedef aliases " +
                "(basic_string<char, …> → string), recursively inside other templates.",
        )
        options.registerOption(
            OPT_LOG_LEVEL,
            Level.INFO,
            null,
            "Suppress diagnostic log and bookmark messages below this level (counters still tracked).",
        )
    }

    fun run(ctx: ImportContext<*>) {
        if (isStabsDone(ctx.program)) return

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
                // Tee the emitting terminal onto ext.log (raw CapturingSink) so tests can inspect
                // output; counting is the shared ext.diagnostics accumulator, tee'd in ImportContext.
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
        const val OPT_LOG_DEGRADATIONS: String = "Log degradations at end-of-run"
        const val OPT_SHORTEN_TYPEDEFS: String = "Shorten templated names via typedefs"
        const val OPT_LOG_LEVEL: String = "Minimum log level"

        @JvmStatic
        fun isStabsDone(program: Program) = program.getOptions(Program.PROGRAM_INFO).getBoolean(OPT_STABS_DONE, false)

        @JvmStatic
        fun markStabsDone(program: Program, value: Boolean) {
            program.runTransaction("Stabs: set done flag") {
                program.getOptions(Program.PROGRAM_INFO).setBoolean(OPT_STABS_DONE, value)
            }
        }
    }
}

data class StabsOptions(
    val createImportedLabels: Boolean = true,
    val applyPlateComments: Boolean = true,
    val applyVtables: Boolean = true,
    val logDegradations: Boolean = false,
    val shortenTypedefs: Boolean = false,
    val minLogLevel: Level = Level.INFO,
) {
    constructor(opts: Options) : this(
        applyPlateComments = opts.getBoolean(StabsAnalyzer.OPT_PLATE_COMMENTS, true),
        applyVtables = opts.getBoolean(StabsAnalyzer.OPT_VTABLES, true),
        logDegradations = opts.getBoolean(StabsAnalyzer.OPT_LOG_DEGRADATIONS, false),
        shortenTypedefs = opts.getBoolean(StabsAnalyzer.OPT_SHORTEN_TYPEDEFS, false),
        minLogLevel = opts.getEnum(StabsAnalyzer.OPT_LOG_LEVEL, Level.INFO),
    )
}
