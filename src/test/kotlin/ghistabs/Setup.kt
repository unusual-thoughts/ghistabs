package ghistabs

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvest
import ghistabs.harvest.Harvester
import ghistabs.harvest.StabCursor
import ghistabs.harvest.TypeResolver
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.materialize.TypeRegistry

/**
 * Program-less [AddressResolver] for harvest unit tests: builds addresses in a standalone generic space
 * and resolves no names (name→address lookup needs a Program's symbol table). Harvest only ever calls
 * [buildAddress] / [ghistabs.importer.AddressResolver.stabAddress], never [resolve].
 */
object GenericAddressResolver : AddressResolver {
    override val sink: DiagnosticSink = DummySink

    // Size is in *bits* — 8 caps the space at 0xff, so any realistic stab value throws
    // AddressOutOfBounds. One shared instance: addresses from different spaces don't compare.
    private val space = GenericAddressSpace("generic", 64, AddressSpace.TYPE_RAM, 0)

    override fun buildAddress(offset: Long): Address = space.getAddress(offset)

    override fun resolve(name: String): Address? = null
}

fun dummyHarvester() = Harvester(
    monitor = TaskMonitor.DUMMY,
    sink = DummySink,
    resolver = GenericAddressResolver,
)

fun dummyCursor() = StabCursor(GenericAddressResolver, DummySink)

// Tests capture at max verbosity — DEBUG and up — so log assertions see every message.
fun Program.defaultContext() = ImportContext(
    this,
    TaskMonitor.DUMMY,
    // overlaySection off: the decoded-struct .stab overlay is a diagnostic view, not needed to produce
    // types, and it's ~8% of the run. StabSectionOverlayIntegrationTest exercises it directly.
    StabsOptions(minLogLevel = Level.DEBUG, overlaySection = false),
    CapturingSink(),
    StabsDiagnostics(),
)

fun ImportContext<*>.defaultTypeRegistry(): TypeRegistry {
    val harvest = Harvest.of(mapOf())
    return TypeRegistry(dtm, this, diagnostics, harvest, TypeResolver.Empty)
}
