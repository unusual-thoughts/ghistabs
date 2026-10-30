package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.abi.itanium.VirtualBases
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportProbe

/**
 * Lays the virtual bases a class struct lacks where its Itanium vtable says they are
 * ([VirtualBases]), on whatever class structs the program has. After [GccVftableAnalyzer] and the
 * Demangler analyzer, whose labels it finds classes by, and after the Stabs Importer, whose recorded class
 * structs it falls back on.
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
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val laid = VirtualBases(program, sink).placeAll()
        if (laid > 0) log.appendMsg(NAME, "laid $laid virtual base(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium virtual bases"
    }
}
