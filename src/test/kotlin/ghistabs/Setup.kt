package ghistabs

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.*
import ghistabs.harvest.HarvestIndex
import ghistabs.harvest.Harvester
import ghistabs.harvest.StabCursor
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.materialize.DataTypeRegistry

/**
 * Program-less [AddressResolver] for harvest unit tests: builds addresses in a standalone generic space
 * and resolves no names (name→address lookup needs a Program's symbol table). Harvest only ever calls
 * [buildAddress] / [ghistabs.importer.AddressResolver.stabAddress], never [resolve].
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

fun ImportContext<*>.defaultTypeRegistry() = DataTypeRegistry(dtm, this, diagnostics, HarvestIndex.Empty)
