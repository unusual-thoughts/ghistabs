package ghicpp.analyzers

import ghicpp.recover.MethodClassPass
import ghicpp.recover.MethodClassPass.Companion.isMethodClassesGuessed
import ghicpp.recover.MethodClassPass.Companion.markMethodClassesGuessed
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.AnalysisProbe
import ghidrakt.diagnose.MessageLogSink
import ghidrakt.diagnose.report
import ghidrakt.isAnalyzerEnabled

/**
 * Guess the class of each unnamed function that takes a `this`, off the objects its callers pass it
 * ([MethodClassPass]), once a class pass (MSVC or Itanium RTTI classes, or vftables from pointer tables) or a
 * stabs import has recorded the classes and put their methods, constructors included, in them. The pass moves
 * nothing more when run again over the same classes, so a run returns at once where one already ran since a
 * class pass last recorded classes ([isMethodClassesGuessed]). A class pass that auto-analysis may not follow
 * with this, as a one-time run of *Vftables from pointer tables*, asks for a run of it after ([followClassPass]).
 */
class MethodClassAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Move each unnamed function that takes a `this` into the class its callers pass it objects of, " +
            "or the base of it that does as much",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // After MSVC RTTI classes, Itanium RTTI classes and Vftables from pointer tables, whose methods and
        // constructors are the evidence.
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        if (program.isMethodClassesGuessed) return true
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val moved = MethodClassPass(program, sink).run(monitor)
        if (moved > 0) report("guessed the class of $moved function(s)")
        program.markMethodClassesGuessed()
        return true
    }

    companion object {
        const val NAME = "Method classes from this"

        /**
         * Have a run of this follow the class pass that just ran on [program], when this is enabled: a one-time
         * run, with this analyzer's own options, at its priority. In auto-analysis this analyzer's own run comes
         * first, and the follow-up finds the guesses made and returns; a one-time class pass runs alone.
         */
        fun followClassPass(program: Program, set: AddressSetView) {
            if (!program.isAnalyzerEnabled(NAME)) return
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.getAnalyzer(NAME)?.let { mgr.scheduleOneTimeAnalysis(it, set) }
        }
    }
}
