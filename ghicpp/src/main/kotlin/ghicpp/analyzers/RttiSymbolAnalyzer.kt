package ghicpp.analyzers

import ghicpp.abi.itanium.RttiSymbolPass
import ghicpp.abi.itanium.RttiSymbolPass.Companion.RTTI_SYMBOLS_RESTORED
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.MessageLogSink
import ghidrakt.diagnose.report

/**
 * Puts back the `_ZTS`/`_ZTI`/`_ZTV` labels a stripped gcc binary lost, from the RTTI it kept
 * ([RttiSymbolPass]). Early, so everything keyed off those symbols sees them: the Demangler analyzer's
 * `vtable`/`typeinfo` labels, [TypeinfoLayoutAnalyzer], [VtableSweepAnalyzer] and the stabs import's classes.
 * Needs only memory and the block permissions.
 */
class RttiSymbolAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Label the typeinfos, type names and vtables a stripped gcc binary's RTTI still holds",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.FORMAT_ANALYSIS.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = !program[RTTI_SYMBOLS_RESTORED] && GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val laid = RttiSymbolPass.runOnce(program, MessageLogSink(log, originator = NAME))
        if (laid > 0) report("labelled $laid vtable(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium RTTI symbols"
    }
}
