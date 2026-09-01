package ghistabs.test

import ghidra.framework.options.OptionType
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions
import ghistabs.diagnose.*
import ghistabs.harvest.*
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.materialize.DataTypeRegistry
import ghistabs.runTransaction

/**
 * Program-less [AddressResolver] for harvest unit tests: builds addresses in a standalone generic space
 * and resolves no names (name→address lookup needs a Program's symbol table). Harvest only ever calls
 * [buildAddress] / [stabAddress], never [resolve].
 */
object GenericAddressResolver : AddressResolver {
    // Size is in *bits* — 8 caps the space at 0xff, so any realistic stab value throws
    // AddressOutOfBounds. One shared instance: addresses from different spaces don't compare.
    private val space = GenericAddressSpace("generic", 64, AddressSpace.TYPE_RAM, 0)

    override fun buildAddress(offset: Long): Address = space.getAddress(offset)

    override fun resolve(name: String): Address? = null
}

fun dummyHarvester() = CountingSink().let {
    it to Harvester(
        monitor = TaskMonitor.DUMMY,
        sink = it,
        resolver = GenericAddressResolver,
    )
}

fun dummyCursor() = StabCursor(GenericAddressResolver, DummySink)

// Tests capture at max verbosity — DEBUG and up — so log assertions see every message.
fun Program.defaultContext() = ImportContext(
    this,
    TaskMonitor.DUMMY,
    // overlaySection off: the decoded-struct .stab overlay is a diagnostic view, not needed to produce
    // types, and it's ~8% of the run. StabSectionOverlayIntegrationTest exercises it directly.
    ImportOptions(minLogLevel = Level.DEBUG, overlaySection = false),
    CapturingSink(),
    StabsDiagnostics(),
)

fun indexOf(vararg asts: Type) = HarvestIndex(
    Harvest(
        types = asts.associateBy { it.id },
        rawCollisions = emptyMap(),
        sources = emptyMap(),
        textRanges = emptyMap(),
    ),
    foldSources = false,
)

fun ImportContext<*>.defaultTypeRegistry() = DataTypeRegistry(dtm, this, diagnostics, indexOf())

/**
 * Disable WindowsResourceReferenceAnalyzer before autoanalysis. On PE binaries it runs a Ghidra script
 * (findScriptByName → GhidraScriptUtil.getScriptSourceDirectories), which NPEs under the test harness —
 * there's no OSGi bundle host and no user-settings dir to start one. It's irrelevant to stabs import, so
 * turn it off. Opens its own transaction.
 */
fun Program.disableWindowsResourceAnalyzer() = runTransaction("disable-windows-resource-analyzer") {
    getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("WindowsResourceReference", false)
}

/**
 * Turn off every boolean analyzer option whose name contains one of `-PdisableAnalyzers=<a>,<b>`
 * (case-insensitive). Lets a probe be run twice against one fixture — once with an analyzer, once
 * without — and the two output trees diffed, with no recompile between them. Returns what it disabled.
 */
fun Program.disableAnalyzersFromProperty(): List<String> {
    val needles = System.getProperty("disableAnalyzers").orEmpty()
        .split(',').map(String::trim).filter(String::isNotEmpty)
    if (needles.isEmpty()) return emptyList()
    val analysis = getOptions(Program.ANALYSIS_PROPERTIES)
    val hits = analysis.optionNames.filter { name ->
        analysis.getType(name) == OptionType.BOOLEAN_TYPE && needles.any { name.contains(it, ignoreCase = true) }
    }
    runTransaction("disable-analyzers") { hits.forEach { analysis.setBoolean(it, false) } }
    return hits
}
