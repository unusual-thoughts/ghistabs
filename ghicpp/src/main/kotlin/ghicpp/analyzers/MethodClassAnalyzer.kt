package ghicpp.analyzers

import ghicpp.recover.MethodClassPass
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
 * nothing more when run again over an unchanged program, so a run right after another of this instance, with no
 * change to the program between, by an analyzer or a user, returns at once ([isUpToDate]). A class pass that
 * auto-analysis may not follow with this, as a one-time run of *Vftables from pointer tables*, asks for a run of
 * it after ([followClassPass]).
 */
class MethodClassAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Move each unnamed function that takes a `this` into the class its callers pass it objects of, " +
            "or the base of it that does as much",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    /** The program this last ran on, by [Program.getUniqueProgramID], and its modification number then. */
    private var lastRun: Pair<Long, Long>? = null

    init {
        // After MSVC RTTI classes, Itanium RTTI classes and Vftables from pointer tables, whose methods and
        // constructors are the evidence.
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        if (isUpToDate(program)) return true
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val moved = MethodClassPass(program, sink).run(monitor)
        if (moved > 0) report("guessed the class of $moved function(s)")
        lastRun = program.uniqueProgramID to program.modificationNumber
        return true
    }

    /** Whether this ran on [program] and nothing changed it since: a run now would move nothing more. */
    fun isUpToDate(program: Program) = lastRun == program.uniqueProgramID to program.modificationNumber

    companion object {
        const val NAME = "Method classes from this"

        /**
         * Have a run of this follow the class pass that just ran on [program], when this is enabled: a one-time
         * run of auto-analysis's instance, with this analyzer's own options, at its priority. In auto-analysis that
         * instance's own run comes first, with nothing between, and the follow-up returns at once
         * ([isUpToDate]); a one-time class pass runs alone.
         */
        fun followClassPass(program: Program, set: AddressSetView) {
            if (!program.isAnalyzerEnabled(NAME)) return
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.getAnalyzer(NAME)?.let { mgr.scheduleOneTimeAnalysis(it, set) }
        }
    }
}
