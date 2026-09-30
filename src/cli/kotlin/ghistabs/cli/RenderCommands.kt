package ghistabs.cli

import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.required
import com.github.ajalt.clikt.parameters.types.file
import ghistabs.entrypoints.StabsRenderExporter.Companion.ELIDE_SJLJ
import ghistabs.entrypoints.StabsRenderExporter.Companion.LINE_ALIGNED
import ghistabs.entrypoints.StabsRenderExporter.Companion.SHOW_STORAGE
import ghistabs.importer.ImportContext
import ghistabs.render.Renderer

/** Renders every source file into [outDir] in [mode], on top of the import. */
internal abstract class RenderCommand(name: String) : ImportingCommand(name = name) {
    protected abstract val mode: Renderer.Mode

    private val outDir by option("-d", "--target-dir", help = "Directory to write the rendered per-source files into")
        .file(canBeFile = false).required()
    private val varStorage by option("--var-storage", help = SHOW_STORAGE.desc)
        .flag("--no-var-storage", default = SHOW_STORAGE.default)
    private val lineAligned by option(
        "--line-aligned",
        help = "Render source line n at output line n, blank rows and all, instead of collapsing blank runs",
    ).flag("--no-line-aligned", default = LINE_ALIGNED.default)

    /** Only decomp exposes it: a skeleton has no decompiled statements to mark. */
    protected open val provenance = true

    override fun ImportContext<*>.execute() {
        val artifacts = fullImport() ?: return
        Renderer(
            mode,
            this,
            artifacts.hints,
            showStorage = varStorage,
            lineAligned = lineAligned,
            provenance = provenance,
        ).use { renderer ->
            val written = renderer.renderAll(outDir, monitor)
            log("render", "rendered ${renderer.sources.size} sources -> $written files in $outDir")
        }
        saveFull()
    }
}

internal class SkeletonCommand : RenderCommand(name = "skeleton") {
    override fun help(context: Context) =
        "Reconstruct a line-aligned source skeleton per file (types, signatures, locals, N_SLINE map)."

    override val mode = Renderer.Mode.SKELETON
}

internal class DecompCommand : RenderCommand(name = "decomp") {
    override fun help(context: Context) =
        "Render decompilation per source file (elides gcc SjLj exception scaffolding by default)."

    private val elideSjlj by option("--elide-sjlj", help = ELIDE_SJLJ.desc)
        .flag("--no-elide-sjlj", default = ELIDE_SJLJ.default)
    override val mode get() = if (elideSjlj) Renderer.Mode.ELIDE_SJLJ else Renderer.Mode.DECOMPILE

    override val provenance by option(
        "--line-numbers",
        help = "Mark each decompiled statement with the source line its code came from, /* ⇐ L n */",
    ).flag("--no-line-numbers", default = true)
}
