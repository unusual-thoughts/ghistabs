package ghistabs.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.UsageError
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.file
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.framework.options.OptionType
import ghidra.program.model.listing.Program
import ghidra.program.util.GhidraProgramUtilities
import ghistabs.entrypoints.NO_RETURN_ANALYZER_NAME
import ghistabs.entrypoints.StabsAnalyzer
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportOptions
import ghistabs.importer.ImportOptions.Companion.CLASSES
import ghistabs.importer.ImportOptions.Companion.FOLD_SOURCES
import ghistabs.importer.ImportOptions.Companion.SHORTEN_TYPEDEFS
import ghistabs.importer.ImportOptions.Companion.VFPTR_MODEL
import ghistabs.importer.ImportOptions.Companion.isStabsDone
import ghistabs.importer.ImportOptions.Companion.markStabsDone
import ghistabs.materialize.cpp.VfptrModel
import ghistabs.runTransaction
import java.io.File

/** Runs the whole import, and so is the only thing the import's own options mean anything to. */
internal abstract class ImportingCommand(name: String) : StabsCommand(name = name) {
    private val sourceRoots by option(
        "--source-root",
        help = "Directory containing partial original sources from the binary, to correlate and " +
            "improve decompilation output (eg. stdlib)",
    ).file(mustExist = true, canBeFile = false).multiple()
    private val buildClasses by option("--classes", help = CLASSES.desc)
        .flag("--no-classes", default = CLASSES.default)
    private val shortenTypedefs by option("--shorten-typedefs", help = SHORTEN_TYPEDEFS.desc)
        .flag("--no-shorten-typedefs", default = SHORTEN_TYPEDEFS.default)
    private val foldSources by option("--fold-sources", help = FOLD_SOURCES.desc)
        .flag("--no-fold-sources", default = FOLD_SOURCES.default)
    private val vfptrModel by option("--vfptr-model", help = VFPTR_MODEL.desc)
        .enum<VfptrModel>().default(VFPTR_MODEL.default)
    private val disableAnalyzers by option(
        "--disable-analyzer",
        help = "turn off every analyzer whose name contains this, case-insensitively (repeatable). " +
            "Render the same binary with and without one to A/B what it actually changes.",
    ).multiple()
    protected val saveDb by option(
        "--save-db",
        help = "Save the program as auto-analysis left it, before the stabs import, to this file as a Ghidra " +
            "packed database (.gzf). Pass that file instead of the binary to skip the analysis next time.",
    ).file(canBeDir = false)
    protected val saveDbFull by option(
        "--save-db-full",
        help = "Save the program once the command is done with it, import and render included, to this file as " +
            "a Ghidra packed database (.gzf): to open in Ghidra, or pass back in (it is imported again).",
    ).file(canBeDir = false)

    override val options get() = ImportOptions().also { o ->
        o.applyPlateComments = false
        o.buildClasses = buildClasses
        o.shortenTypedefs = shortenTypedefs
        o.foldSources = foldSources
        o.minLogLevel = shared.logLevel
        o.overlaySection = false
        o.vfptrModel = vfptrModel
        o.sourceRoots = sourceRoots.map { it.path }
    }

    /**
     * Full auto-analysis, then the whole import, then every dump. A program that comes in analyzed —
     * a `.gzf` from `--save-db` — skips the analysis, and one that comes in imported is imported
     * again, as `Tools > Stabs > Re-import` does. `--save-db` snapshots the point between the two, as
     * the tests' AnalysisCache does; `--save-db-full` is [saveFull]'s.
     */
    protected fun ImportContext<*>.fullImport(): ImportArtifacts? {
        if (program.isStabsDone) {
            warn("import", "program already carries a stabs import; importing again")
            program.markStabsDone(false)
        }
        if (program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
            log("analysis", "program is already analyzed; skipping auto-analysis")
            if (disableAnalyzers.isNotEmpty()) {
                warn("analysis", "--disable-analyzer has no effect on an analyzed program")
            }
        } else {
            autoAnalyze()
        }
        saveDb?.let { savePacked(it, "the analyzed program") }
        return import().artifacts?.also {
            shared.dumpRecords(it.records)
            shared.dumpHarvest(it.harvest)
            shared.dumpRegistry(it)
            shared.dumpDegradations(diagnostics)
        }
    }

    /** `--save-db-full`, the program as this command leaves it: called last, after any render. */
    protected fun ImportContext<*>.saveFull() {
        saveDbFull?.let { savePacked(it, "the imported program") }
    }

    private fun ImportContext<*>.savePacked(file: File, what: String) {
        file.parentFile?.mkdirs()
        // saveToPackedFile will not replace a file, and a rerun into the same path is the usual case.
        file.delete()
        program.saveToPackedFile(file, monitor)
        log("save-db", "saved $what to $file")
    }

    // Import ourselves (StabsAnalyzer disabled) instead of scheduling it into autoanalysis, so we keep
    // the ImportContext it populates
    private fun ImportContext<*>.autoAnalyze() {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        program.runTransaction("cli-disable-stabs-analyzer") {
            val analysis = program.getOptions(Program.ANALYSIS_PROPERTIES)
            analysis.setBoolean(StabsAnalyzer.NAME, false)
            disableAnalyzers.flatMap { needle ->
                analysis.optionNames.filter {
                    it.contains(needle, ignoreCase = true) && analysis.getType(it) == OptionType.BOOLEAN_TYPE
                }
            }.forEach {
                analysis.setBoolean(it, false)
                debug("analyzers", "disabled analyzer: $it")
            }
        }
        mgr.initializeOptions()
        // Production-mode ClassSearcher scans a jar only at `<X>/(lib|build/libs)/<X>*.jar`; see buildCli.
        check(NO_RETURN_ANALYZER_NAME in program.getOptions(Program.ANALYSIS_PROPERTIES).optionNames) {
            "ClassSearcher registered none of ghistabs' analyzers; the cli jar is not at ghistabs-cli/lib/"
        }
        mgr.reAnalyzeAll(null)
        program.runTransaction("cli-auto-analyze") {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
        }
        // What Ghidra's own analyze paths set, and what fullImport reads back off a `.gzf`.
        GhidraProgramUtilities.markProgramAnalyzed(program)
    }
}

/** Import only, for the JSON/degradation dumps — no decompiler, no rendered output. */
internal class DumpCommand : ImportingCommand(name = "dump") {
    override fun help(context: Context) =
        "Import and write the requested dumps only (at least one of --records/--harvest/--registry/" +
            "--degradation-log/--save-db/--save-db-full)."

    override fun validate() = with(shared) {
        val saves = listOfNotNull(this@DumpCommand.saveDb, this@DumpCommand.saveDbFull)
        if (listOfNotNull(recordsJson, harvestJson, registryJson, degradationLog).isEmpty() && saves.isEmpty()) {
            throw UsageError(
                "nothing to dump: pass --records, --harvest, --registry, --degradation-log, --save-db or --save-db-full",
            )
        }
    }

    override fun ImportContext<*>.execute() {
        fullImport()
        saveFull()
    }
}
