package ghicpp.entrypoints

import ghicpp.abi.itanium.Itanium
import ghicpp.abi.itanium.ItaniumRttiParser
import ghicpp.recover.VirtualBasePass
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.AnalysisProbe
import ghistabs.diagnose.MessageLogSink
import ghistabs.diagnose.report

/**
 * Places the virtual bases a class struct lacks where its Itanium vtable says they are ([VirtualBasePass] over
 * [ItaniumRttiParser.withVtables]), on whatever class structs the program has. After [VtableSweepAnalyzer] and
 * the Demangler analyzer, whose labels it finds classes by, and after the Stabs Importer, whose recorded
 * class structs it falls back on.
 */
class VirtualBaseAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Lay the virtual bases a gcc class struct lacks where its Itanium vtable and typeinfo say they are",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val placed = VirtualBasePass(program, Itanium, sink).placeAll(ItaniumRttiParser(program, sink).withVtables())
        if (placed > 0) report("placed $placed virtual base(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium virtual bases"
    }
}
