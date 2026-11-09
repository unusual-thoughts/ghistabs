package ghicpp.analyzers

import ghicpp.eh.SjljLsda
import ghicpp.eh.SjljLsdaPass
import ghicpp.eh.SjljRegistrationFinder
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.AnalysisProbe
import ghistabs.diagnose.MessageLogSink

/**
 * Lays the LSDA of every function MinGW's gcc built with SJLJ exceptions ([SjljLsdaPass]): the
 * header, call-site, action and type tables [SjljLsda] reads, each field typed and commented,
 * labelled `lsda` in the namespace of the function it belongs to, and that function's receiver
 * ([SjljLsdaPass.layReceiver]).
 *
 * Ghidra's `GCC Exception Handlers` analyzer lays the same tables, but finds them through the
 * `.eh_frame` FDEs of DWARF unwinding, which an SJLJ binary has none of, and reads DWARF call-site
 * records, which SJLJ's are not. The only pointer to an SJLJ LSDA is in its function's prologue,
 * which fills an `_Unwind_SjLj_Function_context` before `_Unwind_SjLj_Register`, the personality
 * routine and then the LSDA, one word above it, usually back to back but sometimes with the
 * scheduler's other prologue stores in between:
 * ```
 * movl $___gxx_personality_sj0, -0x28(%ebp)
 * movl $LLSDA123, -0x24(%ebp)
 * ```
 * so the pair is what this looks for, in the bytes, before or without disassembly
 * ([SjljRegistrationFinder.find]), the personality being whatever most pairs store first, which a stripped
 * binary leaves unnamed ([SjljRegistrationFinder.lsdas]).
 *
 * Runs before the Stabs Importer, whose data-coverage report would otherwise count every table
 * gcc linked into `.text` as undescribed data. The type table's pointers show whatever labels its
 * typeinfo objects get, from the symbol table or the import, so nothing here depends on those.
 */
class SjljLsdaAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Lay the exception tables (LSDA) of gcc SJLJ exception handling, found through the personality " +
            "and LSDA a function stores in its unwind context.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // Before the Filler Byte Condenser: the padding after a landing pad's `call _Unwind_SjLj_Resume`
        // only leads an undefined run once the receiver and its pads are disassembled.
        priority = AnalysisPriority.LOW_PRIORITY.before().before()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = SjljRegistrationFinder.canFind(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val laid = SjljLsdaPass(program, sink).run(set, monitor)
        if (laid > 0) log.appendMsg(NAME, "laid $laid LSDA(s)")
        return true
    }

    companion object {
        const val NAME = "GCC SJLJ exception tables"
    }
}
