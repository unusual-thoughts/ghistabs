package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportOptions.Companion.isStabsDone
import ghistabs.materialize.VtableVirtualBases
import ghistabs.parse.StabReader

/**
 * Lays the virtual bases a class struct lacks where its Itanium vtable says they are
 * ([VtableVirtualBases]), on whatever class structs the program has. After [GccVftableAnalyzer] and the
 * Demangler analyzer, whose labels it finds classes by. The stabs import runs it itself once its labels
 * are demangled, with its own fallback for classes no namespace finds, so this does nothing on a program
 * with stabs. Disabling this analyzer turns the import's pass off too ([isEnabled]).
 */
class VirtualBaseAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Lay the virtual bases a gcc class struct lacks where its Itanium vtable and typeinfo say they are",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        if (program.isStabsDone || StabReader.hasStabs(program)) return false
        val laid = VtableVirtualBases(program, MessageLogSink(log, originator = NAME)).layAll()
        if (laid > 0) log.appendMsg(NAME, "laid $laid virtual base(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium virtual bases"

        /** Whether the analyzer is on in [program]'s analysis options, which the stabs import honours too. */
        fun isEnabled(program: Program) = program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(NAME, true)
    }
}
