package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.eh.SjljApplier
import ghistabs.cpp.eh.SjljLsda
import ghistabs.cpp.eh.SjljLsdaApplier
import ghistabs.cpp.eh.sjljLsdas
import ghistabs.cpp.eh.sjljRegistrations
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportProbe

/**
 * Lays the LSDA of every function MinGW's gcc built with SJLJ exceptions ([SjljLsdaApplier]): the
 * header, call-site, action and type tables [SjljLsda] reads, each field typed and commented,
 * labelled `lsda` in the namespace of the function it belongs to, and that function's receiver
 * ([SjljApplier.layReceiver]).
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
 * ([sjljRegistrations]), the personality being whatever most pairs store first, which a stripped
 * binary leaves unnamed ([sjljLsdas]).
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

    /** gcc's, as [GnuDemangler.canDemangle] decides it, on 32-bit x86: the only prologue [sjljRegistrations] reads. */
    override fun canAnalyze(program: Program) = program.language.processor.toString() == "x86" &&
        !program.language.isBigEndian &&
        program.defaultPointerSize == 4 &&
        GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, originator = NAME))
        val stored = program.sjljLsdas(set, monitor)
        val applier = SjljApplier(program, monitor, sink)
        stored.values.flatMap { it.registrations }.forEach { applier.layReceiver(it) }
        val laid = SjljLsdaApplier(program, monitor, sink).layAll(stored)
        if (laid > 0) log.appendMsg(NAME, "laid $laid LSDA(s)")
        return true
    }

    companion object {
        const val NAME = "GCC SJLJ exception tables"
    }
}
