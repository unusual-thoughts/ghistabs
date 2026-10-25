package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.eh.SjljAbi
import ghistabs.cpp.eh.SjljApplier
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportProbe

/**
 * Types gcc's SJLJ exception ABI ([SjljAbi]) where a program uses it, through [SjljApplier]: the
 * `SjLj_Function_Context` each registering function keeps on its stack, as a local `fc`, with the
 * `__builtin_setjmp` buffer gcc's stabs leave out; a comment on each `fc.call_site` store saying what
 * its landing pad catches; and the libgcc and libsupc++ entry points the unwinding goes through, the
 * `_Unwind_SjLj_*` calls, the personality routines and the `__cxa_*` throw and catch calls, wherever
 * nothing more definite than analysis has typed them.
 *
 * The registrations are [SjljLsdaAnalyzer]'s, which runs before the Stabs Importer and lays each
 * function's LSDA and receiver. Its priority puts this after the Stabs Importer, so a type the stabs
 * on libgcc define is the one used, and a signature they give is left as it is.
 */
class SjljContextAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Type the SJLJ function context gcc functions with exception handling keep, and the libgcc and " +
            "libsupc++ exception entry points.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = SjljLsdaAnalyzer().canAnalyze(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        // Byte analyzers run again on whatever code a later analyzer changes (call fixups re-add theirs),
        // so only what [set] covers: the whole program once, then just the changed code.
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val (contexts, signatures) = SjljApplier(program, monitor, sink).applyAll(set)
        if (contexts + signatures > 0) log.appendMsg(NAME, "typed $contexts context(s), $signatures entry point(s)")
        return true
    }

    companion object {
        const val NAME = "GCC SJLJ unwind context"
    }
}
