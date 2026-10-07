package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program
import ghidra.program.model.util.CodeUnitInsertionException
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.MessageLogSink
import ghistabs.forceCreateData
import ghistabs.materialize.DtmRegistry
import ghistabs.materialize.cpp.abi.Rtti
import ghistabs.materialize.cpp.abi.isTypeinfo
import ghistabs.materialize.cpp.abi.resolveLayout

/**
 * Lays a typeinfo struct at every `_ZTI` symbol. The stabs import also calls [layTypeinfos] itself,
 * before its vtable sweep and coverage report: a stab global can give a typeinfo its only `_ZTI` label,
 * which this analyzer, run before the import, would never see. Disabling this analyzer turns the
 * import's pass off too ([isEnabled]).
 */
class RttiLayoutAnalyzer :
    AbstractAnalyzer(NAME, "Lay structs at every gcc Itanium typeinfo `_ZTI` symbol", AnalyzerType.BYTE_ANALYZER) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        val laid = layTypeinfos(program, DtmRegistry(program.dataTypeManager), MessageLogSink(log, Level.DEBUG, NAME))
        if (laid > 0) log.appendMsg(NAME, "laid $laid typeinfo(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium typeinfo"

        /** Whether the analyzer is on in [program]'s analysis options, which the stabs import honours too. */
        fun isEnabled(program: Program) = program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(NAME, true)

        /** Lay a struct at every typeinfo symbol not already typed as one, into [registry]; returns how many. */
        fun layTypeinfos(program: Program, registry: DtmRegistry, sink: DiagnosticSink): Int {
            val reader = Rtti.Reader(program)
            var laid = 0
            for (sym in program.symbolTable.symbolIterator.iterator().asSequence()
                .filter { it.isTypeinfo }
                .distinctBy { it.address }
                .filter { program.listing.getDataAt(it.address)?.dataType !is Structure }) {
                val name = sym.path.joinToString("::")
                val dt = reader.structFor(sym.address)?.let(registry::resolveLayout) ?: run {
                    sink.debug("typeinfo-unread", name, sym.address)
                    continue
                }
                try {
                    program.forceCreateData(sym.address, dt)
                    laid += 1
                } catch (e: CodeUnitInsertionException) {
                    sink.warn("typeinfo-lay-error", "${dt.name} for $name: $e", sym.address)
                }
            }
            return laid
        }
    }
}
