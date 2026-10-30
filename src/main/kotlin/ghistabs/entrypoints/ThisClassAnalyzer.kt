package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.recover.ThisClasses
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportProbe

/**
 * Guess the class of each unnamed function that takes a `this`, off the objects its callers pass it
 * ([ThisClasses]), once a class pass (MSVC or Itanium RTTI classes) or a stabs import has recorded the
 * classes and put their methods, constructors included, in them.
 */
class ThisClassAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Move each unnamed function that takes a `this` into the class its callers pass it objects of, " +
            "or the base of it that does as much",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // After MSVC RTTI classes and Itanium RTTI classes, whose methods and constructors are the evidence.
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val moved = ThisClasses(program, sink).guess(monitor)
        if (moved > 0) log.appendMsg(NAME, "guessed the class of $moved function(s)")
        return true
    }

    companion object {
        const val NAME = "Method classes from this"
    }
}
