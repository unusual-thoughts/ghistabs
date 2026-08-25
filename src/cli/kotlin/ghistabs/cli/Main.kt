package ghistabs.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.NoOpCliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.file
import ghidra.GhidraApplicationLayout
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.script.GhidraScriptUtil
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.framework.Application
import ghidra.framework.HeadlessGhidraApplicationConfiguration
import ghidra.framework.options.OptionType
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghistabs.ImportOptions
import ghistabs.StabsAnalyzer
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.diagnose.*
import ghistabs.importer.ImportArtifacts
import ghistabs.importer.ImportContext
import ghistabs.render.Mode
import ghistabs.render.Renderer
import ghistabs.runTransaction

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
    private val elideSjlj by option(
        "--elide-sjlj",
        help = "elide gcc SjLj exception scaffolding from the decompilation (default; no-op on ELF/DWARF-EH)",
    ).flag("--no-elide-sjlj", default = true)
    override val mode get() = if (elideSjlj) Mode.ELIDE_SJLJ else Mode.DECOMPILE
}

/**
 * Freestanding headless driver: boot Ghidra, load [binary], run the stabs import with the given
 * [ImportOptions], optionally emit the record/harvest/registry JSON dumps, then render every source
 * into [outDir] in [mode]. Mirrors the pipeline the analyzer + render probes run, but from a `main()`
 * rather than a Ghidra tool or an integration test.
 *
 * The import log streams live to stderr (filtered at `--log-level`); `--log FILE` redirects it there.
 */
private abstract class RenderCommand(name: String, help: String) : CliktCommand(name = name, help = help) {
    protected abstract val mode: Mode

    private val binary by argument(help = "ELF/PE binary carrying .stab/.stabstr debug info (gcc 3.2–12)")
        .file(mustExist = true, canBeDir = false, mustBeReadable = true)
    private val outDir by option("-d", "--target-dir", help = "directory to write the rendered per-source files into")
        .file(canBeFile = false).required()

    private val buildClasses by option("--classes", help = ImportOptions.CLASSES.desc)
        .flag("--no-classes", default = ImportOptions.CLASSES.default)
    private val shortenTypedefs by option("--shorten-typedefs", help = ImportOptions.SHORTEN_TYPEDEFS.desc)
        .flag("--no-shorten-typedefs", default = ImportOptions.SHORTEN_TYPEDEFS.default)
    private val varStorage by option(
        "--var-storage",
        help = "annotate each local with the storage gcc gave it, (stack) or (reg)",
    ).flag("--no-var-storage", default = false)
    private val lineAligned by option(
        "--line-aligned",
        help = "render source line n at output line n, blank rows and all, instead of collapsing blank runs",
    ).flag("--no-line-aligned", default = false)
    private val foldSources by option("--fold-sources", help = ImportOptions.FOLD_SOURCES.desc)
        .flag("--no-fold-sources", default = ImportOptions.FOLD_SOURCES.default)

    private val logLevel by option("-v", "--log-level", help = "minimum level streamed to the log").enum<Level>()
        .default(Level.INFO)
    private val sourceRoots by option("--source-root", help = ImportOptions.SOURCE_ROOTS.desc)
        .file(mustExist = true, canBeFile = false).multiple()
    private val disableAnalyzers by option(
        "--disable-analyzer",
        help = "turn off every analyzer whose name contains this, case-insensitively (repeatable). " +
            "Render the same binary with and without one to A/B what it actually changes.",
    ).multiple()

    private val recordsJson by option("--records-json", help = "dump parsed StabRecords as JSON").file(canBeDir = false)
    private val harvestJson by option("--harvest-json", help = "dump the harvest as JSON").file(canBeDir = false)
    private val registryJson by option("--registry-json", help = "dump type registry as JSON").file(canBeDir = false)
    private val logFile by option("--log", help = "redirect the live import log to this file as well as stdout")
        .file(canBeDir = false)
    private val degradationLog by option("--degradation-log", help = "write grouped materialization degradations here")
        .file(canBeDir = false)

    private val options get() = ImportOptions(
        false,
        buildClasses,
        shortenTypedefs,
        foldSources,
        logLevel,
        false,
        sourceRoots = sourceRoots.map { it.path },
    )

    override fun run() {
        val monitor = BarLoggerMonitorSink(options.minLogLevel)
        Msg.setErrorLogger(monitor)
        if (!Application.isInitialized()) {
            Application.initializeApplication(GhidraApplicationLayout(), HeadlessGhidraApplicationConfiguration())
        }
        val fileWriter = logFile?.also { it.parentFile?.mkdirs() }?.bufferedWriter()
            ?.also { echo("log -> $logFile") }
        val fileSink = fileWriter?.let { StreamSink(options.minLogLevel, it) }

        // WindowsResourceReferenceAnalyzer runs a named script during PE autoanalysis; start the OSGi
        // bundle host (as HeadlessAnalyzer does) so its GhidraScriptUtil.bundleHost lookup isn't null.
        GhidraScriptUtil.acquireBundleHostReference()
        Msg.setErrorLogger(monitor)
        val msgLog = MessageLog()
        try {
            ProgramLoader.builder().source(binary).compiler("gcc").log(msgLog).monitor(monitor).load().use { results ->
                val program = results.getPrimaryDomainObject(this)
                try {
                    val ctx = ImportContext(
                        program,
                        monitor,
                        options,
                        TeeSink(monitor, fileSink),
                        StabsDiagnostics(),
                    )
                    ctx.autoAnalyze()
                    // No transaction: every write inside opens its own — the materialize/apply/
                    // source-map passes, [StabSectionOverlay], and the done-flags through
                    // `Program.set` — which is what the analyzer path relies on already.
                    val artifacts = ctx.import().artifacts
                    fileWriter?.apply {
                        msgLog.toString().takeIf { it.isNotBlank() }?.let { append("--- loader MessageLog ---\n$it\n") }
                    }

                    ctx.writeDumps(artifacts)
                    ctx.render(artifacts)
                } finally {
                    program.release(this)
                }
            }
        } finally {
            GhidraScriptUtil.releaseBundleHostReference()
            fileWriter?.close()
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
            analysis.setBoolean(StabsAnalyzer.NAME, false)
            disableAnalyzers.flatMap { needle ->
                analysis.optionNames.filter {
                    it.contains(needle, ignoreCase = true) && analysis.getType(it) == OptionType.BOOLEAN_TYPE
                }
            }.forEach {
                analysis.setBoolean(it, false)
                echo("disabled analyzer: $it")
            }
        }
        mgr.initializeOptions()
        mgr.reAnalyzeAll(null)
        program.runTransaction("cli-auto-analyze") {
            mgr.startAnalysis(monitor)
            mgr.waitForAnalysis(null, monitor)
        }
    }

    private fun ImportContext<*>.writeDumps(artifacts: ImportArtifacts?) {
        recordsJson?.let { f ->
            artifacts?.records?.let { records ->
                f.parentFile?.mkdirs()
                f.writeText(dumpJson.encodeToString(records))
            }
        }
        harvestJson?.let { f ->
            artifacts?.harvest?.let { harvest ->
                f.parentFile?.mkdirs()
                f.writeText(dumpJson.encodeToString(harvest))
            }
        }
        registryJson?.let { f ->
            artifacts?.writeRegistryDump(f)
        }
        degradationLog?.let { f ->
            val byCategory = diagnostics.snapshotDegradations()
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

    private fun ImportContext<*>.render(artifacts: ImportArtifacts?) {
        artifacts ?: return
        Renderer(
            artifacts.index,
            program,
            mode,
            resolver,
            showStorage = varStorage,
            lineAligned = lineAligned,
            sink = this,
        ).use { renderer ->
            val written = renderer.renderAll(outDir)
            echo("rendered ${renderer.sources.size} sources -> $written files in $outDir")
        }
    }
}
