package ghistabs.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.NoOpCliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.file
import ghidra.GhidraApplicationLayout
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.script.GhidraScriptUtil
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.StabsOptions
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.diagnose.dumpJson
import ghistabs.diagnose.writeRegistryDump
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.parse.StabReader
import ghistabs.render.Mode
import ghistabs.render.Renderer
import ghistabs.runTransaction
import kotlinx.serialization.encodeToString
import java.io.Flushable

fun main(args: Array<String>) = NoOpCliktCommand(name = "ghidra-stabs")
    .subcommands(SkeletonCommand(), DecompCommand())
    .main(args)

private class SkeletonCommand :
    RenderCommand(
        name = "skeleton",
        help = "Reconstruct a line-aligned source skeleton per file (types, signatures, locals, N_SLINE map).",
    ) {
    override val mode = Mode.SKELETON
}

private class DecompCommand :
    RenderCommand(
        name = "decomp",
        help = "Render decompilation per source file (elides gcc SjLj exception scaffolding by default).",
    ) {
    // Cygwin/PE binaries use SjLj EH, so elision is the readable default; --no-elide-sjlj yields the
    // raw decompilation (Mode.DECOMPILE). Either way a no-op on DWARF-EH (ELF).
    private val elideSjlj by option("--elide-sjlj").flag("--no-elide-sjlj", default = true)
    override val mode get() = if (elideSjlj) Mode.ELIDE_SJLJ else Mode.DECOMPILE
}

/**
 * Freestanding headless driver: boot Ghidra, load [binary], run the stabs import with the given
 * [StabsOptions], optionally emit the record/harvest/registry JSON dumps, then render every source
 * into [outDir] in [mode]. Mirrors the pipeline the analyzer + render probes run, but from a `main()`
 * rather than a Ghidra tool or an integration test.
 *
 * The import log streams live to stderr (filtered at `--log-level`); `--log FILE` redirects it there.
 */
private abstract class RenderCommand(name: String, help: String) : CliktCommand(name = name, help = help) {
    protected abstract val mode: Mode

    private val binary by argument(help = "PE/ELF binary carrying .stab/.stabstr debug info (Cygwin gcc)")
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)

    private val outDir by option("-d", "--target-dir", help = "directory to write the rendered per-source files into")
        .file(canBeFile = false).required()

    private val plateComments by option("--plate-comments").flag("--no-plate-comments", default = true)
    private val vtables by option("--vtables").flag("--no-vtables", default = true)
    private val shortenTypedefs by option("--shorten-typedefs").flag("--no-shorten-typedefs", default = false)
    private val foldSources by option("--fold-sources").flag("--no-fold-sources", default = true)
    private val overlaySection by option("--overlay-section").flag("--no-overlay-section", default = true)
    private val logLevel by option("--log-level", help = "minimum level streamed to the log").enum<Level>()
        .default(Level.INFO)

    private val recordsJson by option("--records-json", help = "dump parsed StabRecords as JSON").file(canBeDir = false)
    private val harvestJson by option("--harvest-json", help = "dump the harvest as JSON").file(canBeDir = false)
    private val registryJson by option("--registry-json", help = "dump type registry as JSON").file(canBeDir = false)
    private val logFile by option("--log", help = "redirect the live import log to this file instead of stderr")
        .file(canBeDir = false)
    private val degradationLog by option("--degradation-log", help = "write grouped materialisation degradations here")
        .file(canBeDir = false)

    private val options get() =
        StabsOptions(plateComments, vtables, shortenTypedefs, foldSources, logLevel, overlaySection)

    override fun run() {
        if (!Application.isInitialized()) {
            Application.initializeApplication(GhidraApplicationLayout(), HeadlessGhidraApplicationConfiguration())
        }
        val monitor = TaskMonitor.DUMMY
        val msgLog = MessageLog()
        val consumer = Any()
        val writer = logFile?.also { it.parentFile?.mkdirs() }?.bufferedWriter()
        val out = writer ?: System.err
        writer?.let { echo("log -> $logFile") }
        // WindowsResourceReferenceAnalyzer runs a named script during PE autoanalysis; start the OSGi
        // bundle host (as HeadlessAnalyzer does) so its GhidraScriptUtil.bundleHost lookup isn't null.
        GhidraScriptUtil.acquireBundleHostReference()
        try {
            ProgramLoader.builder().source(binary).compiler("gcc").log(msgLog).monitor(monitor).load().use { results ->
                val program = results.getPrimaryDomainObject(consumer)
                try {
                    autoAnalyze(program, monitor)
                    val ctx = ImportContext(program, monitor, options, StreamSink(logLevel, out), StabsDiagnostics())
                    program.runTransaction("stabs-cli-import") { ctx.import() }
                    msgLog.toString().takeIf { it.isNotBlank() }?.let { out.append("--- loader MessageLog ---\n$it\n") }

                    writeDumps(program, ctx)
                    render(program, ctx)
                } finally {
                    program.release(consumer)
                }
            }
        } finally {
            GhidraScriptUtil.releaseBundleHostReference()
            writer?.close()
        }
    }

    // Let autoanalysis (esp. the demangler) settle first with our analyzer off, then import manually
    // so the run honours the CLI's StabsOptions rather than the program options DB.
    private fun autoAnalyze(program: Program, monitor: TaskMonitor) {
        val mgr = AutoAnalysisManager.getAnalysisManager(program)
        program.runTransaction("cli-disable-stabs-analyzer") {
            program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean(StabsAnalyzer.NAME, false)
        }
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        program.runTransaction("cli-auto-analyze") {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
        }
    }

    private fun writeDumps(program: Program, ctx: ImportContext<*>) {
        recordsJson?.let { f ->
            val records = StabReader.fromProgram(program)!!.readAll().records
            f.parentFile?.mkdirs()
            f.writeText(dumpJson.encodeToString(records))
        }
        harvestJson?.let { f ->
            val records = StabReader.fromProgram(program)!!.readAll().records
            val harvest = program.runTransaction("cli-harvest-dump") { Harvester(ctx).harvest(records) }
            f.parentFile?.mkdirs()
            f.writeText(dumpJson.encodeToString(harvest))
        }
        registryJson?.let { f ->
            val registry = ctx.typeRegistry
            val resolver = ctx.typeResolver
            if (registry != null && resolver != null) {
                writeRegistryDump(registry, resolver, f)
            } else {
                echo("registry dump skipped: import populated no registry (no stabs?)", err = true)
            }
        }
        degradationLog?.let { f ->
            val byCategory = ctx.diagnostics.snapshotDegradations()
                .groupBy { it.category }.toList().sortedByDescending { it.second.size }
            f.parentFile?.mkdirs()
            f.writeText(
                buildString {
                    appendLine("total degradations: ${byCategory.sumOf { it.second.size }}")
                    appendLine("\ncounts by category:")
                    byCategory.forEach { (cat, list) -> appendLine("  $cat = ${list.size}") }
                    byCategory.forEach { (cat, list) ->
                        appendLine("\n=== $cat (${list.size}) ===")
                        list.forEach { appendLine("  ${it.detail}") }
                    }
                },
            )
        }
    }

    private fun render(program: Program, ctx: ImportContext<*>) {
        val reader = StabReader.fromProgram(program) ?: run {
            echo("no .stab section; nothing to render", err = true)
            return
        }
        val harvest = program.runTransaction("cli-render-harvest") { Harvester(ctx).harvest(reader.readAll().records) }
        Renderer(TypeResolver(harvest, foldSources, ctx), program, mode, ctx.resolver).use { renderer ->
            val written = renderer.renderAll(outDir)
            echo("rendered ${renderer.sources.size} sources -> $written files in $outDir")
        }
    }
}

/** Streams each diagnostic line at or above [minLevel] to [out], flushing so the log is live. */
private class StreamSink(private val minLevel: Level, private val out: Appendable) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message == null || level.ordinal < minLevel.ordinal) return
        val at = address?.let { " at @$it" } ?: ""
        out.append("[$level][$category]$at $message\n")
        (out as? Flushable)?.flush()
    }
}
