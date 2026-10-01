package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.BookmarkSink
import ghistabs.diagnose.MessageLogSink
import ghistabs.diagnose.TeeSink
import ghistabs.importer.ImportOptions.Companion.isStabsDone
import ghistabs.importer.VtableSweeper
import ghistabs.importer.VtableSweeper.Companion.isVtablesSwept
import ghistabs.materialize.DtmRegistry
import ghistabs.parse.StabReader

const val VTABLE_SWEEP_ANALYZER_NAME = "C++ vtables (from symbols)"

/**
 * Lay a `<Class>_vftable` at every `_ZTV…` (Itanium) or `_vt…` (gcc 2.x) symbol, typed off the
 * functions its slots point at, with the class namespace and `vftable` label Ghidra's RTTI scripts
 * expect. Needs nothing but the symbol table and memory, so it earns its keep on a binary with no
 * stabs at all: every virtual call through such a table then resolves to a named slot.
 *
 * On a binary that carries stabs, the stabs import runs the same [VtableSweeper] itself, after its
 * class pass has claimed the vtables of the classes the stabs describe, which are typed off their
 * declared virtuals rather than off their targets. So this defers to it: it does nothing on a program
 * whose stabs are not imported yet, or whose import already swept ([isVtablesSwept]). What is left is
 * an import run with class reconstruction off, which sweeps nothing, and a binary with no stabs.
 */
class VtableSweepAnalyzer :
    AbstractAnalyzer(
        VTABLE_SWEEP_ANALYZER_NAME,
        "Lay vftable structs at C++ vtable symbols, typed from the functions their slots point at.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // After the Stabs Importer (LOW), which sweeps on its own and marks the program swept, and
        // after the analyzers that settle a function's signature, which a swept slot is typed off.
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = !program.isVtablesSwept

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        if (program.isVtablesSwept) return false
        // Not imported yet: the import sweeps, and knows which tables its classes own.
        if (!program.isStabsDone && StabReader.hasStabs(program)) return false

        val sink = TeeSink(BookmarkSink(program), log?.let(::MessageLogSink))
        val sweeper = VtableSweeper(DtmRegistry(program.dataTypeManager), program, monitor ?: TaskMonitor.DUMMY, sink)
        val laid = sweeper.sweepUnclaimedVtables()
        if (laid > 0) log?.appendMsg(VTABLE_SWEEP_ANALYZER_NAME, "laid $laid vtable(s)")
        return true
    }
}
