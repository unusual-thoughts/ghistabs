package ghicpp.analyzers

import ghicpp.abi.itanium.Typeinfo
import ghicpp.abi.itanium.TypeinfoReader
import ghicpp.abi.itanium.isTypeinfo
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
import ghidrakt.DtmRegistry
import ghidrakt.diagnose.AnalysisProbe
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.diagnose.Level
import ghidrakt.diagnose.MessageLogSink
import ghidrakt.forceCreateData

/**
 * Lays an Itanium typeinfo struct at every `_ZTI` symbol, then fills in the structs of the `__cxxabiv1`
 * typeinfo classes themselves, in place of the empty ones Ghidra made for their methods' `this`. After the
 * Stabs Importer, whose globals give some typeinfos their only `_ZTI` label.
 */
class TypeinfoLayoutAnalyzer :
    AbstractAnalyzer(NAME, "Lay structs at every gcc Itanium typeinfo `_ZTI` symbol", AnalyzerType.BYTE_ANALYZER) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val sink = AnalysisProbe.sinkFor(program, MessageLogSink(log, Level.DEBUG, NAME))
        val registry = DtmRegistry(program.dataTypeManager)
        val laid = program.layTypeinfos(registry, sink).size
        registry.replaceClassStubs(sink)
        if (laid > 0) log.appendMsg(NAME, "laid $laid typeinfo(s)")
        return true
    }

    companion object {
        const val NAME = "Itanium typeinfo"

        /** Lay a struct at every typeinfo symbol not already typed as one, into [registry]; returns how many. */
        fun Program.layTypeinfos(registry: DtmRegistry, sink: DiagnosticSink) = TypeinfoReader(this).run {
            buildList {
                for (sym in symbolTable.symbolIterator.iterator().asSequence()
                    .filter { it.isTypeinfo }
                    .distinctBy { it.address }
                    .filter { listing.getDataAt(it.address)?.dataType !is Structure }) {
                    val name = sym.path.joinToString("::")
                    val dt = structFor(sym.address)?.let(registry::resolveLayout) ?: run {
                        sink.debug("typeinfo-unread", name, sym.address)
                        continue
                    }
                    try {
                        add(forceCreateData(sym.address, dt))
                    } catch (e: CodeUnitInsertionException) {
                        sink.warn("typeinfo-lay-error", "${dt.name} for $name: $e", sym.address)
                    }
                }
            }
        }

        /**
         * Replaces the empty structs Ghidra made for the `this` of the `__cxxabiv1` typeinfo classes' methods
         * with their full structs ([Typeinfo.structFor]).
         */
        fun DtmRegistry.replaceClassStubs(sink: DiagnosticSink) {
            val rtti = Typeinfo(dtm)
            val stubs = dtm.allStructures.asSequence()
                .filter { it.isZeroLength || it.numComponents == 0 }
                .mapNotNull { stub -> rtti.structFor(stub.name)?.let { stub to it } }
                .toList()
            for ((stub, layout) in stubs) {
                dtm.replaceDataType(stub, resolveLayout(layout), false)
                sink.debug("vtable-typeinfo-stub-laid", stub.pathName)
            }
        }
    }
}
