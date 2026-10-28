package ghistabs.entrypoints

import ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin.PEUtil
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.abi.MsvcClasses
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportProbe

/**
 * Class records and virtual members off the MSVC RTTI ([MsvcClasses]), for the Class Hierarchy window
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
            "that introduced it",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = PEUtil.isVisualStudioOrClangPe(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val result = MsvcClasses(program, sink).recover()
        if (result.classes > 0) {
            log.appendMsg(
                NAME,
                "${result.classes} class(es), ${result.owned} virtual function(s) owned, ${result.moved} moved, " +
                    "${result.shared} shared",
            )
        }
        return true
    }

    companion object {
        const val NAME = "MSVC RTTI classes"
    }
}
