package ghistabs.cli

import com.github.ajalt.clikt.core.*
import com.github.ajalt.clikt.output.HelpFormatter
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.groups.OptionGroup
import com.github.ajalt.clikt.parameters.groups.provideDelegate
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.file
import ghidra.GhidraApplicationLayout
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.script.GhidraScriptUtil
import ghidra.app.util.importer.MessageLog
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.options.OptionType
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghistabs.diagnose.*
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.entrypoints.StabsRenderExporter.Companion.ELIDE_SJLJ
import ghistabs.entrypoints.StabsRenderExporter.Companion.LINE_ALIGNED
import ghistabs.entrypoints.StabsRenderExporter.Companion.SHOW_STORAGE
import ghistabs.harvest.Harvest
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportOptions
import ghistabs.importer.ImportOptions.Companion.CLASSES
import ghistabs.importer.ImportOptions.Companion.FOLD_SOURCES
import ghistabs.importer.ImportOptions.Companion.SHORTEN_TYPEDEFS
import ghistabs.importer.STABS_ANALYZER_NAME
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.render.Renderer
import ghistabs.runTransaction
import ghistabs.withProgram
import java.io.File

fun main(args: Array<String>) = Ghistabs()
    .subcommands(SkeletonCommand(), DecompCommand(), DumpCommand(), HarvestCommand(), ParseCommand())
    .main(args)

/**
 * Dispatch only: [SharedOptions] is a group each subcommand includes, so those options are typed
 * after the command name and Clikt would never accept them here. It is the same group in every
 * subcommand though, so [allHelpParams] quotes one and the root help lists them too — rendered,
 * never parsed: `ghistabs --records x parse …` remains an error.
 */
private class Ghistabs : NoOpCliktCommand(name = "ghistabs") {
    override fun help(context: Context) =
        "Headless driver for the stabs importer: parse, harvest, import and render gcc STABS debug info."

    override fun allHelpParams() = super.allHelpParams() +
        registeredSubcommands().first().allHelpParams()
            .filterIsInstance<HelpFormatter.ParameterHelp.Option>()
            .filter { it.groupName == SharedOptions.TITLE }
}

/**
 * Where the log goes and which dumps to write: the only options that mean the same thing whatever
 * the command does. Given after the command name, like every other option, and carrying the writers
 * that act on them.
 */
private class SharedOptions : OptionGroup(TITLE) {
    val logLevel by option("-v", "--log-level", help = "Minimum level streamed to the log").enum<Level>()
        .default(Level.INFO)
    val logGhidra by option("--log-ghidra", help = "Also show Ghidra log messages")
        .flag("--log-no-ghidra", default = false)
    val logFile by option("--log", help = "Redirect the import log to this file as well as stdout")
        .file(canBeDir = false)

    val recordsJson by option("--records", help = "Dump parsed StabRecords as JSON").file(canBeDir = false)
    val harvestJson by option("--harvest", help = "Dump the harvest as JSON").file(canBeDir = false)
    val registryJson by option("--registry", help = "Dump type registry as JSON").file(canBeDir = false)
    val degradationLog by option("--degradation-log", help = "Write grouped materialization degradations here")
        .file(canBeDir = false)

    fun dumpRecords(records: List<StabRecord>) = recordsJson?.writeDump { dumpJson.encodeToString(records) }

    fun dumpHarvest(harvest: Harvest) = harvestJson?.writeDump { dumpJson.encodeToString(harvest) }

    fun dumpRegistry(artifacts: ImportArtifacts) = registryJson?.let(artifacts::writeRegistryDump)

    fun dumpDegradations(diagnostics: StabsDiagnostics) = degradationLog?.writeDump {
        val byCategory = diagnostics.snapshotDegradations()
            .groupBy { it.category }.toList().sortedByDescending { it.second.size }
        buildString {
            appendLine("total degradations: ${byCategory.sumOf { it.second.size }}")
            appendLine("\ncounts by category:")
            byCategory.forEach { (cat, list) -> appendLine("  $cat = ${list.size}") }
            byCategory.forEach { (cat, list) ->
                appendLine("\n=== $cat (${list.size}) ===")
                list.forEach { appendLine("  $it") }
            }
        }
    }

    private fun File.writeDump(text: () -> String) {
        parentFile?.mkdirs()
        writeText(text())
    }

    companion object {
        const val TITLE = "Common options"
    }
}

private class SkeletonCommand : RenderCommand(name = "skeleton") {
    override fun help(context: Context) =
        "Reconstruct a line-aligned source skeleton per file (types, signatures, locals, N_SLINE map)."

    override val mode = Renderer.Mode.SKELETON
}

private class DecompCommand : RenderCommand(name = "decomp") {
    override fun help(context: Context) =
        "Render decompilation per source file (elides gcc SjLj exception scaffolding by default)."

    private val elideSjlj by option("--elide-sjlj", help = ELIDE_SJLJ.desc)
        .flag("--no-elide-sjlj", default = ELIDE_SJLJ.default)
    override val mode get() = if (elideSjlj) Renderer.Mode.ELIDE_SJLJ else Renderer.Mode.DECOMPILE
}

/** Import only, for the JSON/degradation dumps — no decompiler, no rendered output. */
private class DumpCommand : ImportingCommand(name = "dump") {
    override fun help(context: Context) =
        "Import and write the requested dumps only (at least one of --records/--harvest/--registry/--degradation-log)."

    override fun validate() = with(shared) {
        if (listOfNotNull(recordsJson, harvestJson, registryJson, degradationLog).isEmpty()) {
            throw UsageError("nothing to dump: pass --records, --harvest, --registry or --degradation-log")
        }
    }

    override fun ImportContext<*>.execute() {
        fullImport()
    }
}

/**
 * Parse + harvest, and nothing else — no auto-analysis, nothing written to the program. Neither
 * pass reads anything Ghidra's analyzers produce, so this finishes in seconds where [DumpCommand]
 * takes minutes. Nothing is materialized, hence no `--registry`.
 */
private class HarvestCommand : StabsCommand(name = "harvest") {
    override fun help(context: Context) =
        "Parse and harvest only, skipping auto-analysis and the import. Requires --harvest FILE."

    override fun validate() {
        if (shared.registryJson != null) throw UsageError("--registry needs a full import; use the dump command")
        if (shared.harvestJson == null) throw UsageError("--harvest FILE is required")
    }

    override fun ImportContext<*>.execute() {
        val stabs = readStabs() ?: return
        shared.dumpRecords(stabs.records)
        val harvest = harvester().harvest(stabs.records)
        shared.dumpHarvest(harvest)
        log("harvest", "harvested ${harvest.types.size} types, ${harvest.functions.size} functions")
    }
}

/** Byte decode only: the records as parsed, before any of them mean anything. */
private class ParseCommand : StabsCommand(name = "parse") {
    override fun help(context: Context) =
        "Parse the .stab section only, without harvesting it. Requires --records FILE."

    override fun validate() {
        if (shared.harvestJson != null || shared.registryJson != null) {
            throw UsageError("parse dumps records only; use harvest or dump")
        }
        if (shared.recordsJson == null) throw UsageError("--records FILE is required")
    }

    override fun ImportContext<*>.execute() {
        val stabs = readStabs() ?: return
        shared.dumpRecords(stabs.records)
        log("parse", "parsed ${stabs.records.size} of ${stabs.totalRecordCount} records")
    }
}

/**
 * Freestanding headless driver: boot Ghidra, load [binary] with the given [ImportOptions], and hand
 * it to the subcommand's [execute] — which takes it as far down the pipeline as that subcommand
 * goes. Mirrors what the analyzer + render probes run, but from a `main()` rather than a Ghidra tool
 * or an integration test.
 *
 * The import log streams live to stderr (filtered at `--log-level`); `--log FILE` redirects it there.
 */
private abstract class StabsCommand(name: String) : CliktCommand(name = name) {
    protected val shared by SharedOptions()

    private val binary by argument(help = "ELF/PE binary carrying .stab/.stabstr debug info (gcc 3.2–12)")
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)

    /** What this subcommand runs against the loaded program, dumps included. */
    protected abstract fun ImportContext<*>.execute()

    /** Pass A's input: the raw records. Null when the program carries no stabs. */
    protected fun ImportContext<*>.readStabs(): StabReader.Result? = StabReader.fromProgram(program)?.readAll(monitor)
        ?: run {
            err("no-stabs", "No .stab/.stabstr block found.")
            null
        }

    /** Checked before Ghidra boots, so a misuse fails in milliseconds rather than after a full analysis. */
    protected open fun validate() = Unit

    /** Only the log level matters until something imports; [ImportingCommand] fills in the rest. */
    protected open val options get() = ImportOptions(minLogLevel = shared.logLevel)

    override fun run() {
        validate()
        val monitor = BarLoggerMonitorSink(options.minLogLevel, currentContext.terminal, shared.logGhidra)
        Msg.setErrorLogger(monitor)
        if (!Application.isInitialized()) {
            Application.initializeApplication(GhidraApplicationLayout(), HeadlessGhidraApplicationConfiguration())
        }
        val fileWriter = shared.logFile?.also { it.parentFile?.mkdirs() }?.bufferedWriter()
            ?.also { monitor.debug("log", "appending to ${shared.logFile}") }
        val fileSink = fileWriter?.let { WriterSink(options.minLogLevel, it) }

        // WindowsResourceReferenceAnalyzer runs a named script during PE autoanalysis; start the OSGi
        // bundle host (as HeadlessAnalyzer does) so its GhidraScriptUtil.bundleHost lookup isn't null.
        GhidraScriptUtil.acquireBundleHostReference()
        Msg.setErrorLogger(monitor)
        val msgLog = MessageLog()
        try {
            withProgram(binary, log = msgLog, monitor = monitor) { program ->
                val ctx = ImportContext(program, monitor, options, TeeSink(monitor, fileSink), StabsDiagnostics())
                ctx.execute()
                fileWriter?.apply {
                    msgLog.toString().takeIf { it.isNotBlank() }?.let { append("--- loader MessageLog ---\n$it\n") }
                }
            }
        } finally {
            monitor.stop()
            GhidraScriptUtil.releaseBundleHostReference()
            fileWriter?.close()
        }
    }
}

/** Runs the whole import, and so is the only thing the import's own options mean anything to. */
private abstract class ImportingCommand(name: String) : StabsCommand(name = name) {
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
    private val disableAnalyzers by option(
        "--disable-analyzer",
        help = "turn off every analyzer whose name contains this, case-insensitively (repeatable). " +
            "Render the same binary with and without one to A/B what it actually changes.",
    ).multiple()

    override val options get() = ImportOptions(
        false,
        buildClasses,
        shortenTypedefs,
        foldSources,
        shared.logLevel,
        false,
        sourceRoots = sourceRoots.map { it.path },
    )

    /** Full auto-analysis, then the whole import, then every dump. */
    protected fun ImportContext<*>.fullImport(): ImportArtifacts? {
        autoAnalyze()
        // No transaction: every write inside opens its own — the materialize/apply/source-map
        // passes, [StabSectionOverlay], and the done-flags through `Program.set` — which is what
        // the analyzer path relies on already.
        return import().artifacts?.also {
            shared.dumpRecords(it.records)
            shared.dumpHarvest(it.harvest)
            shared.dumpRegistry(it)
            shared.dumpDegradations(diagnostics)
        }
    }

    // Import ourselves (StabsAnalyzer disabled) instead of scheduling it into autoanalysis, so we keep
    // the ImportContext it populates — the record/harvest/registry dumps read its cached records,
    // harvest, typeRegistry and typeResolver. Scheduling the analyzer (the CONCURRENT path) would match
    // the GUI/plugin workflow more faithfully, but it builds its own private context, leaving those
    // caches unreachable. Ordering holds either way: full autoanalysis runs the demangler (~897) before
    // our import, exactly as StabsAnalyzer's LOW_PRIORITY guarantees in the analyzer path.
    private fun ImportContext<*>.autoAnalyze() {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        program.runTransaction("cli-disable-stabs-analyzer") {
            val analysis = program.getOptions(Program.ANALYSIS_PROPERTIES)
            analysis.setBoolean(STABS_ANALYZER_NAME, false)
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
        mgr.reAnalyzeAll(null)
        program.runTransaction("cli-auto-analyze") {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
        }
    }
}

/** Renders every source file into [outDir] in [mode], on top of the import. */
private abstract class RenderCommand(name: String) : ImportingCommand(name = name) {
    protected abstract val mode: Renderer.Mode

    private val outDir by option("-d", "--target-dir", help = "Directory to write the rendered per-source files into")
        .file(canBeFile = false).required()
    private val varStorage by option("--var-storage", help = SHOW_STORAGE.desc)
        .flag("--no-var-storage", default = SHOW_STORAGE.default)
    private val lineAligned by option(
        "--line-aligned",
        help = "Render source line n at output line n, blank rows and all, instead of collapsing blank runs",
    ).flag("--no-line-aligned", default = LINE_ALIGNED.default)

    override fun ImportContext<*>.execute() {
        val artifacts = fullImport() ?: return
        Renderer(
            mode,
            artifacts.hints,
            program,
            resolver,
            showStorage = varStorage,
            lineAligned = lineAligned,
            sink = this,
        ).use { renderer ->
            val written = renderer.renderAll(outDir, monitor)
            log("render", "rendered ${renderer.sources.size} sources -> $written files in $outDir")
        }
    }
}
