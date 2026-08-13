package ghistabs

import ghidra.app.util.DomainObjectService
import ghidra.app.util.Option
import ghidra.app.util.OptionException
import ghidra.app.util.exporter.Exporter
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.HelpLocation
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions.Companion.isStabsDone
import ghistabs.diagnose.DummySink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.Harvester
import ghistabs.importer.ImportContext
import ghistabs.parse.StabReader
import ghistabs.render.Mode
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
sealed class StabsRenderExporter(name: String, extension: String) :
    Exporter(name, extension, HelpLocation("Stabs", "Stabs_Export_Decompilation")) {
    protected abstract val mode: Mode

    private var outputDir = ""
    private var showStorage = false
    private var lineAligned = false

    override fun supportsAddressRestrictedExport() = false

    override fun canExportDomainObject(domainObject: DomainObject?) =
        domainObject is Program && StabReader.hasStabs(domainObject)

    override fun getOptions(domainObjectService: DomainObjectService) = listOf(
        OutputDirectoryOption(OUTPUT_DIR, outputDir),
        Option(SHOW_STORAGE, showStorage),
        Option(LINE_ALIGNED, lineAligned),
    )

    override fun setOptions(options: List<Option>) = options.forEach(::apply)

    protected open fun apply(option: Option) {
        when (option.name) {
            OUTPUT_DIR -> outputDir = (option.value as? String).orEmpty().trim()
            SHOW_STORAGE -> showStorage = option.on
            LINE_ALIGNED -> lineAligned = option.on
            else -> throw OptionException("Unknown option: ${option.name}")
        }
    }

    protected val Option.on
        get() = value as? Boolean ?: throw OptionException("Invalid type for option: $name")

    override fun export(file: File, domainObj: DomainObject, addrSet: AddressSetView?, monitor: TaskMonitor): Boolean {
        val program = domainObj as? Program
            ?: return log("Unsupported type: ${domainObj.javaClass.name}")
        // The render re-harvests the stabs cheaply, but what it renders is only meaningful once the
        // importer has applied types/locals to the program — require that first.
        if (!program.isStabsDone) {
            return log("Run the Stabs importer first (auto-analysis, or Tools > Stabs > Re-import).")
        }
        val records = StabReader.fromProgram(program)?.readAll()?.records
            ?: return log("No stabs found in this program.")
        val options = StabsOptions(program)
        val ctx = ImportContext(program, monitor, options, DummySink, StabsDiagnostics())
        val harvest = program.runTransaction("stabs-export-harvest") {
            Harvester(ctx).harvest(records)
        }
        val dir = outputDir.takeIf { it.isNotEmpty() }?.let(::File) ?: file
        val written = Renderer(
            HarvestIndex(harvest, options.foldSources, ctx),
            program,
            mode,
            ctx.resolver,
            showStorage = showStorage,
            lineAligned = lineAligned,
        ).use { it.renderAll(dir, monitor) }
        log.appendMsg("Wrote $written files to $dir")
        return true
    }

    private fun log(message: String): Boolean {
        log.appendMsg(message)
        return false
    }

    protected companion object {
        const val OUTPUT_DIR = "Output directory (else the path above, as a directory)"
        const val ELIDE_SJLJ = "Elide gcc SjLj exception scaffolding"
        const val SHOW_STORAGE = "Annotate locals with their storage"
        const val LINE_ALIGNED = "Render source line n at output line n"
    }
}

/** Decompilation per source file, `.decomp`. */
class StabsDecompExporter : StabsRenderExporter("Stabs Decompilation", "decomp") {
    // Cygwin/PE binaries use SjLj EH, so elision is the readable default; off yields the raw
    // decompilation. Either way a no-op on DWARF-EH (ELF).
    private var elideSjlj = true

    override val mode get() = if (elideSjlj) Mode.ELIDE_SJLJ else Mode.DECOMPILE

    override fun getOptions(domainObjectService: DomainObjectService) =
        super.getOptions(domainObjectService) + Option(ELIDE_SJLJ, elideSjlj)

    override fun apply(option: Option) = if (option.name == ELIDE_SJLJ) elideSjlj = option.on else super.apply(option)
}

/** Declarations at their original lines and no code, `.skeleton`. */
class StabsSkeletonExporter : StabsRenderExporter("Stabs Source Skeleton", "skeleton") {
    override val mode = Mode.SKELETON
}
