package ghicpp.analyzers

import ghicpp.ClassRecordSource
import ghicpp.VfptrModel
import ghicpp.abi.itanium.ItaniumRttiParser
import ghicpp.recover.ClassPass
import ghicpp.recover.ClassPass.Companion.FILL_ARRAYS
import ghicpp.recover.ClassPass.Companion.INLINED_CONSTRUCTORS
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.AnalysisProbe
import ghidrakt.diagnose.MessageLogSink
import ghidrakt.diagnose.report

/**
 * Class records and virtual members off the Itanium RTTI ([ItaniumRttiParser]), what [MsvcClassAnalyzer] does
 * for MSVC: on a gcc 3+ binary with no stabs, a stripped one included once [RttiSymbolAnalyzer] has put
 * its RTTI labels back. A binary another [ClassRecordSource] describes (one with stabs) gets its classes from it.
 *
 * After [VtableSweepAnalyzer], whose `vtable` labels it reads.
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

    override fun canAnalyze(program: Program) =
        GnuDemangler().canDemangle(program) && !ClassRecordSource.describedElsewhere(program)

    override fun registerOptions(options: Options, program: Program) =
        options.register(VfptrModel.OPTION, FILL_ARRAYS, INLINED_CONSTRUCTORS)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val pass = ClassPass(program, ItaniumRttiParser(program, sink), sink, program.analyzerOptions(NAME))
        val result = pass.run(monitor)
        if (result.classes > 0) {
            report(
                "${result.classes} class(es), ${result.owned} virtual function(s) owned, ${result.moved} moved, " +
                    "${result.shared} shared, ${result.structors} constructor(s) and destructor(s) named, " +
                    "${result.sized} class size(s) recorded, ${result.filled} struct(s) filled",
            )
        }
        return true
    }

    companion object {
        const val NAME = "Itanium RTTI classes"
    }
}
