package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions.Companion.isOverlayDone
import ghistabs.StabsOptions.Companion.isStabsDone
import ghistabs.StabsOptions.Companion.markOverlayDone
import ghistabs.StabsOptions.Companion.markStabsDone
import ghistabs.StabsOptions.Companion.registerStabs
import ghistabs.diagnose.*
import ghistabs.importer.ImportContext
import ghistabs.importer.StabSectionOverlay
import ghistabs.importer.StabsImporter
import ghistabs.importer.StaticContexts

/**
 * Imports STABS debug info (.stab/.stabstr) into Ghidra: types, function signatures,
 * locals, C++ classes, vtables. Targets PE/ELF binaries produced by Cygwin gcc 3.4.4.
 *
 * Auto-runs once per program (gated by [StabsOptions.STABS_DONE]); re-runnable via the
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
        val mem = program.memory
        return mem.getBlock(".stab") != null && mem.getBlock(".stabstr") != null
    }

    override fun registerOptions(options: Options, program: Program?) = options.registerStabs()

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, msg: MessageLog?): Boolean {
        program ?: return false
        msg ?: return false
        monitor ?: return false
        val options = StabsOptions(program)
        val ext = StaticContexts.get(program)

        ImportContext(
            program,
            monitor,
            options,
            // Bookmark every addressed diagnostic (unconditional); MessageLog gets output at/above minLevel.
            // Tee the emitting terminal onto ext.log (raw CapturingSink) so tests can inspect
            // output; counting is the shared ext.diagnostics accumulator, tee'd in ImportContext.
            terminal = TeeSink(BookmarkSink(program), MessageLogSink(msg, options.minLogLevel), ext?.terminal),
            diagnostics = ext?.diagnostics ?: StabsDiagnostics(),
        ).import()

        return true
    }

    companion object {
        const val NAME = "Stabs Importer"

        @JvmStatic
        fun ImportContext<*>.import() {
            if (program.isStabsDone) return

            if (options.overlaySection && !program.isOverlayDone) {
                debug("stab-section-overlaid", count = StabSectionOverlay(this).apply().toLong())
                program.markOverlayDone()
            }

            val result = StabsImporter(this).run()
            log("done", "import complete: $result")
            program.markStabsDone(true)
        }
    }
}

data class StabsOptions(
    val applyPlateComments: Boolean = true,
    val buildClasses: Boolean = true,
    val shortenTypedefs: Boolean = false,
    val foldSources: Boolean = true,
    val minLogLevel: Level = Level.INFO,
    val overlaySection: Boolean = true,
) {

    companion object {
        const val STABS_DONE: String = "Stabs Imported"
        const val OVERLAY_DONE: String = "Stabs Overlaid"
        const val PLATE_COMMENTS: String = "Apply scope plate comments"
        const val CLASSES: String = "Reconstruct C++ classes"
        const val SHORTEN_TYPEDEFS: String = "Shorten templated names via typedefs"
        const val FOLD_SOURCES: String = "Fold source-file spellings"
        const val LOG_LEVEL: String = "Minimum log level"
        const val OVERLAY_SECTION: String = "Overlay .stab section structs"

        val Program.isStabsDone get() = getOptions(Program.PROGRAM_INFO).getBoolean(STABS_DONE, false)

        fun Program.markStabsDone(value: Boolean) {
            runTransaction("Stabs: set done flag") {
                getOptions(Program.PROGRAM_INFO).setBoolean(STABS_DONE, value)
            }
        }

        val Program.isOverlayDone get() = getOptions(Program.PROGRAM_INFO).getBoolean(OVERLAY_DONE, false)

        fun Program.markOverlayDone() {
            runTransaction("Stabs: set overlay done flag") {
                getOptions(Program.PROGRAM_INFO).setBoolean(OVERLAY_DONE, true)
            }
        }

        fun Options.registerStabs() {
            registerOption(
                PLATE_COMMENTS,
                true,
                null,
                "Apply plate comments at lexical scopes when LBRAC/RBRAC info is present.",
            )
            registerOption(
                CLASSES,
                true,
                null,
                "Reconstruct C++ classes: class namespaces, member methods (this-typed via __thiscall), " +
                    "and <Class>_vftable structs applied at _ZTV for virtual dispatch. Off leaves plain " +
                    "structs — member calls lose their this/args and virtual calls stay unresolved.",
            )
            registerOption(
                SHORTEN_TYPEDEFS,
                false,
                null,
                "Rename long templated datatypes onto their shorter typedef aliases " +
                    "(basic_string<char, …> → string), recursively inside other templates.",
            )
            registerOption(
                FOLD_SOURCES,
                true,
                null,
                "Fold two gcc spellings of one physical header (full include path vs bare " +
                    "#include \"x.h\") onto one rendered output file, by unique basename.",
            )
            registerOption(
                LOG_LEVEL,
                Level.INFO,
                null,
                "Minimum level for MessageLog diagnostic output (bookmarks and counters are unaffected).",
            )
            registerOption(
                OVERLAY_SECTION,
                true,
                null,
                "Overlay a decoded StabRecord struct on every .stab entry (refs into .stabstr and back to code/data).",
            )
        }

//        fun Options.stabs() = StabsOptions(
//            applyPlateComments = getBoolean(PLATE_COMMENTS, true),
//            buildClasses = getBoolean(CLASSES, true),
//            shortenTypedefs = getBoolean(SHORTEN_TYPEDEFS, false),
//            foldSources = getBoolean(FOLD_SOURCES, true),
//            minLogLevel = getEnum(LOG_LEVEL, Level.INFO),
//            overlaySection = getBoolean(OVERLAY_SECTION, true),
//        )
    }

    constructor(opts: Options) : this(
        applyPlateComments = opts.getBoolean(PLATE_COMMENTS, true),
        buildClasses = opts.getBoolean(CLASSES, true),
        shortenTypedefs = opts.getBoolean(SHORTEN_TYPEDEFS, false),
        foldSources = opts.getBoolean(FOLD_SOURCES, true),
        minLogLevel = opts.getEnum(LOG_LEVEL, Level.INFO),
        overlaySection = opts.getBoolean(OVERLAY_SECTION, true),
    )

    constructor(program: Program) : this(
        program.getOptions(Program.ANALYSIS_PROPERTIES).getOptions(StabsAnalyzer.NAME),
    )
}
