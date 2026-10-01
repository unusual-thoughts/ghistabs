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

const val VFTABLE_ANALYZER_NAME = "C++ vftables from vtable symbols"

/**
 * Lay a `<Class>_vftable` at every `_ZTV…` (Itanium) or `_vt…` (gcc 2.x) symbol, typed off the
 * functions its slots point at, with the class namespace and `vftable` label Ghidra's RTTI scripts
 * expect. Needs nothing but the symbol table and memory, so it earns its keep on a binary with no
 * stabs at all: every virtual call through such a table then resolves to a named slot.
 *
 * What Ghidra does for the same tables without it, on a gcc binary:
 * - The Demangler analyzer turns `_ZTV3Foo` into a `DemangledAddressTable`: a `Foo::vtable` label,
 *   a `vtable for Foo` plate comment and untyped pointers up to the next imported symbol. No struct,
 *   no label at the address point, and gcc 2.x's `_vt$3Foo` is not an address table to it at all.
 * - The `Windows x86 PE RTTI Analyzer` builds `vftable`s off MSVC's RTTI only
 *   (`PEUtil.isVisualStudioOrClangPe`), so never on a gcc or MinGW binary.
 * - `RTTIGccClassRecoverer` (`RecoverClassesFromRTTIScript`) is a script, not an analyzer. It finds
 *   vtables through the typeinfo graph, so needs Itanium RTTI and finds nothing in gcc 2.x or under
 *   `-fno-rtti`, and recovers whole classes from their constructors with the decompiler. The
 *   `<Class>_vftable` under `/ClassDataTypes/<Class>/` and the `vftable` label laid here are the
 *   names it uses, so it runs over these tables rather than beside them.
 *
 * On a binary that carries stabs, the stabs import runs the same [VtableSweeper] itself, after its
 * class pass has claimed the vtables of the classes the stabs describe, which are typed off their
 * declared virtuals rather than off their targets. So this defers to it: it does nothing on a program
 * whose stabs are not imported yet, or whose import already swept ([isVtablesSwept]). What is left is
 * an import run with class reconstruction off, which sweeps nothing, and a binary with no stabs.
 */
class VftableAnalyzer :
    AbstractAnalyzer(
        VFTABLE_ANALYZER_NAME,
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
        if (laid > 0) log?.appendMsg(VFTABLE_ANALYZER_NAME, "laid $laid vtable(s)")
        return true
    }
}
