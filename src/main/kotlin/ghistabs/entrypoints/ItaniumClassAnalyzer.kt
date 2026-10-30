package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.abi.itanium.ItaniumClasses
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportProbe
import ghistabs.parse.StabReader

/**
 * Class records and virtual members off the Itanium RTTI ([ItaniumClasses]), what [MsvcClassAnalyzer] does
 * for MSVC: on a gcc 3+ binary with no stabs, a stripped one included once [RttiSymbolsAnalyzer] has put
 * its RTTI labels back. A binary with stabs gets its classes from them.
 *
 * After [GccVftableAnalyzer], whose `vtable` labels it reads.
 */
class ItaniumClassAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Record each class's bases from its Itanium typeinfo, and move each virtual function into the class " +
            "that introduced it, and its destructors off the vtable stores they make",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = GnuDemangler().canDemangle(program) && !StabReader.hasStabs(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val result = ItaniumClasses(program, sink).recover(monitor)
        if (result.classes > 0) {
            log.appendMsg(
                NAME,
                "${result.classes} class(es), ${result.owned} virtual function(s) owned, ${result.moved} moved, " +
                    "${result.shared} shared, ${result.structors} constructor(s) and destructor(s) named, " +
                    "${result.sized} class size(s) recorded, ${result.laid} struct(s) laid",
            )
        }
        return true
    }

    companion object {
        const val NAME = "Itanium RTTI classes"
    }
}
