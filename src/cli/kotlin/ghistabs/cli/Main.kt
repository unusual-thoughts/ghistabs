package ghistabs.cli

import com.github.ajalt.clikt.core.*
import com.github.ajalt.clikt.output.HelpFormatter
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.groups.OptionGroup
import com.github.ajalt.clikt.parameters.groups.provideDelegate
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.file
import ghidra.GhidraApplicationLayout
import ghidra.app.script.GhidraScriptUtil
import ghidra.app.util.importer.MessageLog
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.util.Msg
import ghistabs.diagnose.*
import ghistabs.harvest.Harvest
import ghistabs.harvest.StabCursor
import ghistabs.harvest.Symbol
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportOptions
import ghistabs.isPackedProgram
import ghistabs.loadPackedProgram
import ghistabs.loadProgram
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.StabRecord
import ghistabs.parse.SymbolDecl
import java.io.File

fun main(args: Array<String>) = Ghistabs()
    .subcommands(
        SkeletonCommand(),
        DecompCommand(),
        DumpCommand(),
        HarvestCommand(),
        ParseCommand(),
        DecodeCommand(),
    )
    .main(args)

/**
 * Dispatch only: [SharedOptions] is a group each subcommand includes, so those options are typed
 * after the command name and Clikt would never accept them here. It is the same group in every
 * subcommand though, so [allHelpParams] quotes one and the root help lists them too — rendered,
 * never parsed: `ghistabs --records x parse …` remains an error.
 */
private class Ghistabs : NoOpCliktCommand(name = "ghistabs") {
    override fun help(context: Context) =
        "Headless driver for the stabs importer: decode, parse, harvest, import and render STABS."

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
internal class SharedOptions : OptionGroup(TITLE) {
    val logLevel by option("-v", "--log-level", help = "Minimum level streamed to the log").enum<Level>()
        .default(Level.INFO)
    val logGhidra by option("--log-ghidra", help = "Also show Ghidra log messages")
        .flag("--log-no-ghidra", default = false)
    val logFile by option("--log", help = "Redirect the import log to this file as well as stdout")
        .file(canBeDir = false)

    val recordsJson by option("--records", help = "Dump parsed StabRecords as JSON").file(canBeDir = false)
    val harvestJson by option("--harvest", help = "Dump the harvest as JSON").file(canBeDir = false)
    val registryJson by option("--registry", help = "Dump type registry as JSON").file(canBeDir = false)
    val symbolsJson by option("--symbols", help = "Dump parsed symbol declarations as JSON").file(canBeDir = false)
    val degradationLog by option("--degradation-log", help = "Write grouped materialization degradations here")
        .file(canBeDir = false)

    fun dumpRecords(records: List<StabRecord>) = recordsJson?.writeDump { dumpJson.encodeToString(records) }

    fun dumpHarvest(harvest: Harvest) = harvestJson?.writeDump { dumpJson.encodeToString(harvest) }

    fun dumpSymbols(symbols: List<Symbol<SymbolDecl<GlobalTypeId>>>) = symbolsJson?.writeDump {
        dumpJson.encodeToString(symbols)
    }

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

/**
 * The symbol layer: each record's `name:descriptor…` parsed into a [SymbolDecl], with the cursor's
 * source/function context resolved, but nothing merged into types yet. Between [DecodeCommand]
 * (bytes) and [HarvestCommand] (types) — the level at which `:T` vs `:t`, record type and declaration
 * kind are still separate facts, so it answers questions the harvest has already folded away.
 */
private class ParseCommand : StabsCommand(name = "parse") {
    override fun help(context: Context) =
        "Dump parsed symbol declarations, without harvesting them into types. Requires --symbols FILE."

    override fun validate() {
        if (shared.harvestJson != null || shared.registryJson != null) {
            throw UsageError("parse stops below the harvest; use harvest or dump")
        }
        if (shared.symbolsJson == null) throw UsageError("--symbols FILE is required")
    }

    override fun ImportContext<*>.execute() {
        val stabs = readStabs() ?: return
        shared.dumpRecords(stabs.records)
        // preSeed first: N_BINCL/N_EXCL header ids have to be mounted before any symbol referencing
        // them parses, exactly as the harvester does it.
        val cursor = StabCursor(resolver, this)
        cursor.preSeedHeaders(stabs.records)
        val symbols = cursor.rawSymbols(stabs.records)
        shared.dumpSymbols(symbols)
        log("parse", "parsed ${symbols.size} symbols from ${stabs.records.size} records")
    }
}

/** Byte decode only: the records as read, before any of them mean anything. */
private class DecodeCommand : StabsCommand(name = "decode") {
    override fun help(context: Context) =
        "Decode the .stab section only, without parsing the descriptors. Requires --records FILE."

    override fun validate() {
        if (shared.harvestJson != null || shared.registryJson != null) {
            throw UsageError("decode dumps records only; use harvest or dump")
        }
        if (shared.recordsJson == null) throw UsageError("--records FILE is required")
    }

    override fun ImportContext<*>.execute() {
        val stabs = readStabs() ?: return
        shared.dumpRecords(stabs.records)
        log("decode", "decoded ${stabs.records.size} of ${stabs.totalRecordCount} records")
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
internal abstract class StabsCommand(name: String) : CliktCommand(name = name) {
    protected val shared by SharedOptions()

    private val binary by argument(
        help = "ELF/PE binary carrying .stab/.stabstr debug info (gcc 3.2–12), or a .gzf saved by --save-db",
    )
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)

    /** What this subcommand runs against the loaded program, dumps included. */
    protected abstract fun ImportContext<*>.execute()

    /** Checked before Ghidra boots, so a misuse fails in milliseconds rather than after a full analysis. */
    protected open fun validate() = Unit

    /** Only the log level matters until something imports; [ImportingCommand] fills in the rest. */
    protected open val options get() = ImportOptions { minLogLevel = shared.logLevel }

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
            val loaded = if (isPackedProgram(binary)) {
                loadPackedProgram(binary, monitor)
            } else {
                loadProgram(binary, log = msgLog, monitor = monitor)
            }
            loaded.use {
                val ctx = ImportContext(it.program, monitor, TeeSink(monitor, fileSink), options)
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
