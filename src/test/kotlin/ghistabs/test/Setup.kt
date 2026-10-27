package ghistabs.test

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.OptionType
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.*
import ghistabs.entrypoints.RttiSymbolsAnalyzer
import ghistabs.entrypoints.analyzeAfterImport
import ghistabs.harvest.*
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportOptions
import ghistabs.importer.ImportProbe
import ghistabs.importer.ImportResult
import ghistabs.importer.analyzeDataCoverage
import ghistabs.importer.import
import ghistabs.importer.runOnRecords
import ghistabs.index.SourceHints
import ghistabs.index.SourceIndex
import ghistabs.index.TypeGraph
import ghistabs.isAnalyzerEnabled
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.VfptrModel
import ghistabs.parse.IdInterface
import ghistabs.parse.StabReader
import ghistabs.parse.TypeDecl
import ghistabs.runTransaction
import java.io.File
import java.math.BigInteger

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

/**
 * A [TypeDecl.Range] from bounds that fit a Long, which is every bound a test writes as a literal.
 * Keeping the convenience here rather than as a constructor means production code that rebuilds a Range
 * cannot narrow by accident and still compile.
 */
fun <Id : IdInterface> longRange(inner: Id, min: Long, max: Long) =
    TypeDecl.Range(TypeDecl.Ref(inner), BigInteger.valueOf(min), BigInteger.valueOf(max))

/**
 * The import with what auto-analysis would run around it: the RTTI symbols it needs back first, then
 * [analyzeAfterImport], which reports into this context's counters and sink through a probe
 * ([ImportProbe.sinkFor]), then the data coverage report over all of it. Imports [stabs] where a test
 * builds its records by hand, else what the program's own stab section holds.
 */
fun ImportContext<*>.importAndAnalyze(stabs: StabReader.Result? = null): ImportResult {
    if (ImportProbe.get(program) == null) ImportProbe.install(this)
    RttiSymbolsAnalyzer().takeIf { program.isAnalyzerEnabled(it.name) && it.canAnalyze(program) }?.let {
        program.runTransaction("rtti-symbols") { it.added(program, program.memory, monitor, MessageLog()) }
    }
    return (stabs?.let(::runOnRecords) ?: import()).also {
        program.analyzeAfterImport(monitor)
        if (it.artifacts != null) analyzeDataCoverage()
    }
}

// Tests capture at max verbosity — DEBUG and up — so log assertions see every message.
fun Program.defaultContext(
    shortenTypedefs: Boolean = false,
    vfptrModel: VfptrModel = ImportOptions.VFPTR_MODEL.default,
) = ImportContext(
    this,
    TaskMonitor.DUMMY,
    CapturingSink(),
    // overlaySection off: the decoded-struct .stab overlay is a diagnostic view, not needed to produce
    // types, and it's ~8% of the run. StabSectionOverlayIntegrationTest exercises it directly.
    ImportOptions {
        minLogLevel = Level.DEBUG
        overlaySection = false
        this.shortenTypedefs = shortenTypedefs
        this.vfptrModel = vfptrModel
    },
)

fun harvestOf(vararg asts: Type) = Harvest(
    types = asts.associateBy { it.id },
    rawCollisions = emptyMap(),
    sources = emptyMap(),
    textRanges = emptyMap(),
)

fun typesOf(vararg asts: Type) = TypeGraph(harvestOf(*asts))

/** The three indexes over [harvest], constructed together exactly as [ghistabs.importer.runOnRecords] does. */
fun hintsOf(harvest: Harvest, foldSources: Boolean = true, sink: DiagnosticSink = DummySink) =
    SourceHints(harvest, TypeGraph(harvest, sink), SourceIndex(harvest, foldSources, sink), sink)

fun ImportContext<*>.defaultTypeRegistry(): DataTypeRegistry {
    val harvest = harvestOf()
    val types = TypeGraph(harvest)
    val sources = SourceIndex(harvest, foldSources = false)
    return DataTypeRegistry(dtm, this, diagnostics, SourceHints(harvest, types, sources))
}

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
 * Full auto-analysis of [this] with whatever analyzers its options enable, less the Windows resource one
 * (see [disableWindowsResourceAnalyzer]).
 *
 * Ghidra's own per-analyzer wall times go to [timesFile]. The Gradle listener only reports whole-invocation
 * time, which also carries fixture load, our import and the dumps; this attributes the analysis share to
 * individual analyzers, so a perf change can be localized without a profiler.
 */
fun Program.runAutoAnalysis(monitor: TaskMonitor, timesFile: File) {
    val mgr = AutoAnalysisManager.getAnalysisManager(this)
    disableWindowsResourceAnalyzer()
    mgr.reAnalyzeAll(null)
    runTransaction("auto-analyze") {
        mgr.startAnalysis(monitor)
        mgr.waitForAnalysis(null, monitor)
    }
    timesFile.apply { parentFile.mkdirs() }
        .writeText("total = ${mgr.totalTimeInMillis} ms\n\n${mgr.taskTimesString}")
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
