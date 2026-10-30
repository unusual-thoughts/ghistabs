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
import ghistabs.DtmRegistry
import ghistabs.cpp.abi.itanium.Rtti
import ghistabs.cpp.abi.itanium.isTypeinfo
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.MessageLogSink
import ghistabs.forceCreateData
import ghistabs.importer.ImportProbe

/**
 * Lays a typeinfo struct at every `_ZTI` symbol. After the Stabs Importer, whose globals give some
 * typeinfos their only `_ZTI` label.
 */
class RttiLayoutAnalyzer :
    AbstractAnalyzer(NAME, "Lay structs at every gcc Itanium typeinfo `_ZTI` symbol", AnalyzerType.BYTE_ANALYZER) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = ImportProbe.sinkFor(program, MessageLogSink(log, Level.DEBUG, NAME))
        val laid = layTypeinfos(program, DtmRegistry(program.dataTypeManager), sink)
        if (laid > 0) log.appendMsg(NAME, "laid $laid typeinfo(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium typeinfo"

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
