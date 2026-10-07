package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.MessageLogSink
import ghistabs.importer.ImportOptions.Companion.isStabsDone
import ghistabs.importer.VtableSweeper
import ghistabs.importer.VtableSweeper.Companion.isVtablesSwept
import ghistabs.materialize.DtmRegistry
import ghistabs.parse.StabReader

/**
 * Lay a `<Class>_vftable` at every gcc vtable symbol, Itanium `_ZTV…` (gcc 3 and later, the record
 * behind an rtti header) or gcc 2.x `_vt…` (the record behind a reserved entry), typed off the
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
 * - `RecoverClassesFromRTTIScript` finds vtables through the typeinfo graph, so needs Itanium RTTI
 *   and finds nothing in gcc 2.x or under `-fno-rtti`, and recovers whole classes from their
 *   constructors with the decompiler. The `<Class>_vftable` under `/ClassDataTypes/<ns>/<Class>/`
 *   and the `vftable` label laid here are the names it uses, so shift-S and shift-D work on these
 *   tables. The script itself does not: it takes a struct already under `/ClassDataTypes` at an
 *   address point for one it processed (`RecoveredClassHelper.getFunctionsFromVftable`), so a class
 *   whose table is laid here gets no vftable, constructors or members from it, and its methods'
 *   `this` retyped to a near-empty placeholder. Run it with this analyzer off, and without stabs.
 *
 * This is the one sweep. On a binary with stabs it has to come after the class pass, whose tables are
 * typed off the declared virtuals and which it must leave alone ([ghistabs.materialize.cpp.abi.isVtableClaimed]
 * knows them by their labels). So the stabs import calls [sweep] itself as soon as its classes are
 * laid, on its own registry and diagnostics, and the analyzer does nothing on a program whose stabs
 * are not imported yet, or one already swept ([isVtablesSwept]). Disabling this analyzer turns the
 * import's sweep off too ([isEnabled]).
 */
class GccVftableAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Lay a typed <Class>_vftable at every gcc C++ vtable symbol: Itanium `_ZTV…` (gcc 3 and later) " +
            "and gcc 2.x `_vt…`, with each slot typed from the function it points at.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // After the Stabs Importer (LOW), which runs this sweep itself and marks the program swept, and
        // after the analyzers that settle a function's signature, which a swept slot is typed off.
        priority = AnalysisPriority.LOW_PRIORITY.after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    /**
     * gcc's, as the Demangler analyzer decides it ([GnuDemangler.canDemangle]): ELF, Mach-O, a
     * compiler Ghidra recognised as gcc (MinGW, Cygwin), or anything not built for Windows. An MSVC PE
     * has no `_ZTV`/`_vt` symbols to find, so this only saves the symbol walk.
     */
    override fun canAnalyze(program: Program) = !program.isVtablesSwept && GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        if (program.isVtablesSwept) return false
        // Not imported yet: the import sweeps once its classes have claimed their tables.
        if (!program.isStabsDone && StabReader.hasStabs(program)) return false

        // The log only, at INFO and up: no bookmarks. Every table laid would get an Analysis one, and its
        // label and struct already mark it; what goes wrong (an empty table) is a WARN, so it is logged.
        val sink = MessageLogSink(log, originator = "GccVftableAnalyzer")
        val laid = sweep(program, DtmRegistry(program.dataTypeManager), monitor, sink)
        if (laid > 0) log.appendMsg(NAME, "laid $laid vtable(s)")
        return true
    }

    companion object {
        const val NAME = "GCC C++ vftables"

        /** Whether the analyzer is on in [program]'s analysis options, which the stabs import honours too. */
        fun isEnabled(program: Program) = program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(NAME, true)

        /** Lay every vtable no class claimed, into [registry]; returns how many primaries it laid. */
        fun sweep(program: Program, registry: DtmRegistry, monitor: TaskMonitor, sink: DiagnosticSink) =
            VtableSweeper(registry, program, monitor, sink).sweepUnclaimedVtables()
    }
}
