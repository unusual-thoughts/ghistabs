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
import java.util.Collections
import java.util.WeakHashMap

/**
 * Guess the class of each unnamed function that takes a `this`, off the objects its callers pass it
 * ([MethodClassPass]), once a class pass (MSVC or Itanium RTTI classes, or vftables from pointer tables) or a
 * stabs import has recorded the classes and put their methods, constructors included, in them. A class pass
 * that auto-analysis may not follow with this, as a one-time run of *Vftables from pointer tables*, asks for a
 * run of this after it ([followClassPass]).
 */
class MethodClassAnalyzer private constructor(private val followUp: Boolean) :
    AbstractAnalyzer(
        NAME,
        "Move each unnamed function that takes a `this` into the class its callers pass it objects of, " +
            "or the base of it that does as much",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    constructor() : this(followUp = false)

    init {
        // After MSVC RTTI classes, Itanium RTTI classes and Vftables from pointer tables, whose methods and
        // constructors are the evidence.
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        // A follow-up that a run since the class pass already answered, as auto-analysis runs one, has nothing to do.
        if (!pending.remove(program) && followUp) return true
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val moved = MethodClassPass(program, sink).run(monitor)
        if (moved > 0) report("guessed the class of $moved function(s)")
        return true
    }

    companion object {
        const val NAME = "Method classes from this"

        /** The programs with a class pass that ran since the last run of this. */
        private val pending: MutableSet<Program> = Collections.synchronizedSet(Collections.newSetFromMap(WeakHashMap()))

        /**
         * Have a run of this follow the class pass that just ran on [program], when this is enabled: a one-time
         * run, with this analyzer's own options, at its priority. Auto-analysis runs this after the class passes
         * anyway, ahead of the follow-up, which then has nothing to do; a one-time class pass runs alone.
         */
        fun followClassPass(program: Program, set: AddressSetView) {
            if (!program.isAnalyzerEnabled(NAME)) return
            pending += program
            AutoAnalysisManager.getAnalysisManager(program)
                .scheduleOneTimeAnalysis(MethodClassAnalyzer(followUp = true), set)
        }
    }
}
