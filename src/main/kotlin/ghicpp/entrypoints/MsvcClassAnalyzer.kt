package ghicpp.entrypoints

import ghicpp.VfptrModel
import ghicpp.abi.msvc.MsvcRttiParser
import ghicpp.recover.ClassPass
import ghicpp.recover.ClassPass.Companion.FILL_ARRAYS
import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.analyzerOptions
import ghistabs.diagnose.AnalysisProbe
import ghistabs.diagnose.MessageLogSink
import ghistabs.diagnose.report
import ghistabs.register

/**
 * Class records and virtual members off the MSVC RTTI ([MsvcRttiParser]), for the Class Hierarchy window
 * on a binary with nothing else to say about its classes. Ghidra's `Windows x86 PE RTTI Analyzer` lays
 * and labels the RTTI and the vftables, in class namespaces, but records no base and moves no method:
 * only `RecoverClassesFromRTTIScript` does, and it keeps its hierarchy in a struct description.
 *
 * Late, after that analyzer and after the functions its vftables point at have been made.
 */
class MsvcClassAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Record each class's bases from its MSVC RTTI, and move each virtual function into the class " +
            "that introduced it, and its constructors and destructors off the vftable stores they make",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = PEUtil.isVisualStudioOrClangPe(program)

    override fun registerOptions(options: Options, program: Program) = options.register(VfptrModel.OPTION, FILL_ARRAYS)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val pass = ClassPass(program, MsvcRttiParser(program, sink), sink, program.analyzerOptions(NAME))
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
        const val NAME = "MSVC RTTI classes"
    }
}
