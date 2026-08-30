package ghistabs

import ghidra.app.util.DomainObjectService
import ghidra.app.util.Option
import ghidra.app.util.exporter.Exporter
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.HelpLocation
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions.Companion.isStabsDone
import ghistabs.diagnose.MessageLogSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.Harvester
import ghistabs.importer.ImportContext
import ghistabs.parse.StabReader
import ghistabs.render.Renderer
import java.io.File

/**
 * `File > Export Program…`: reconstructs the per-source-file render — the same output the headless
 * driver and the integration harness write. Its two modes are two exporters rather than one option,
 * because `getDefaultFileExtension()` is final on [Exporter]: the extension is fixed at construction,
 * so `.decomp` vs `.skeleton` can only come from separate instances. They read as the headless
 * driver's two subcommands do, picked in the format combo.
 *
 * The render is one file per source, but the export dialog only takes a file path and its browse
 * button is hardwired to `FILES_ONLY` ([ghidra.app.plugin.core.exporter.ExporterDialog] builds that
 * chooser privately, so no exporter can reach it). Hence [OUTPUT_DIR], an option that *is* a
 * directory chooser; left empty, the chosen path is used as the output directory instead — which is
 * what the extension the dialog appends to it is for.
 */
sealed class StabsRenderExporter(name: String, extension: String, val options: StabOptions = StabOptions()) :
    Exporter(name, extension, HelpLocation("Stabs", "Stabs_Export_Decompilation")),
    StabOption.Set by options {
    protected abstract val mode: Renderer.Mode

    // Declaring the property is what enrols the option, here and in any subclass — see [OptionSet].
    private val outputDir by OUTPUT_DIR
    private val showStorage by SHOW_STORAGE
    private val lineAligned by LINE_ALIGNED

    private val sink = MessageLogSink(log)

    override fun supportsAddressRestrictedExport() = false

    override fun canExportDomainObject(domainObjectClass: Class<out DomainObject>) =
        Program::class.java.isAssignableFrom(domainObjectClass)

    override fun canExportDomainObject(domainObject: DomainObject?) =
        domainObject is Program && StabReader.hasStabs(domainObject)

    override fun getOptions(srv: DomainObjectService) = options.export()

    override fun setOptions(new: List<Option>) = options.import(new)

    override fun export(file: File, domainObj: DomainObject, addrSet: AddressSetView?, monitor: TaskMonitor): Boolean {
        val program = domainObj as? Program ?: return err("Unsupported type: ${domainObj.javaClass}")
        // The render re-harvests the stabs cheaply, but what it renders is only meaningful once the
        // importer has applied types/locals to the program — require that first.
        if (!program.isStabsDone) {
            return err("Run the Stabs importer first (auto-analysis, or Tools > Stabs > Re-import).")
        }
        val records = StabReader.fromProgram(program)?.readAll()?.records
            ?: return err("No stabs found in this program.")
        val options = ImportOptions(program)
        val ctx = ImportContext(program, monitor, options, sink, StabsDiagnostics())
        val harvest = Harvester(ctx).harvest(records)

        val dir = outputDir.takeIf { it.isNotEmpty() }?.let(::File) ?: file
        val written = Renderer(
            HarvestIndex(harvest, options.foldSources, ctx),
            program,
            mode,
            ctx.resolver,
            showStorage = showStorage,
            lineAligned = lineAligned,
            sink = ctx,
        ).use { it.renderAll(dir, monitor) }
        sink.log("export", "Wrote $written files to $dir")
        return true
    }

    private fun err(message: String): Boolean {
        sink.err("export", message)
        return false
    }

    companion object {
        val OUTPUT_DIR = DirectoryOption(
            "Output directory (else the path above, as a directory)",
            "Where the per-source files are written. Empty means the path chosen in the dialog, " +
                "taken as a directory.",
        )
        val ELIDE_SJLJ = BoolOption(
            "Elide gcc SjLj exception scaffolding",
            "Drop the __Unwind_SjLj_* calls, personality store and per-call-site index writes gcc " +
                "emits for exceptions. No-op on DWARF-EH (ELF).",
            true,
        )
        val SHOW_STORAGE = BoolOption(
            "Annotate locals with their storage",
            "Mark each local with the storage gcc gave it, (stack) or (reg)",
            false,
        )
        val LINE_ALIGNED = BoolOption(
            "Render source line n at output line n",
            "Keep blank runs instead of collapsing them, so the render diffs against the real source.",
            false,
        )
    }
}

/** Decompilation per source file, `.decomp`. */
class StabsDecompExporter : StabsRenderExporter("Stabs Decompilation", "decomp") {
    // Cygwin/PE binaries use SjLj EH, so elision is the readable default; off yields the raw
    // decompilation. Either way a no-op on DWARF-EH (ELF).
    private val elideSjlj by ELIDE_SJLJ

    override val mode get() = if (elideSjlj) Renderer.Mode.ELIDE_SJLJ else Renderer.Mode.DECOMPILE
}

/** Declarations at their original lines and no code, `.skeleton`. */
class StabsSkeletonExporter : StabsRenderExporter("Stabs Source Skeleton", "skeleton") {
    override val mode = Renderer.Mode.SKELETON
}
