package ghicpp.analyzers

import ghicpp.stl.MsvcRuntime
import ghicpp.stl.MsvcStlApplier
import ghicpp.stl.StlLayouts
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.report

/**
 * Lays out the standard library classes a program uses from the MSVC runtime it imports, off the layouts
 * of that runtime bundled with ghicpp ([MsvcStlApplier]): the demangler knows a
 * `std::basic_string<char,…>` method's `this` only as an empty struct.
 *
 * After the Microsoft demangler, which makes those placeholders, and before the class passes.
 */
class MsvcStlAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Fill the empty std classes the demangler makes for the methods a program imports from " +
            "MSVCP140.DLL, MSVCP140D.DLL or MSVCP90.DLL with that runtime's layouts",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // The demangler analyzers run at DATA_TYPE_PROPOGATION.before().before().before().
        priority = AnalysisPriority.DATA_TYPE_PROPOGATION.before().before()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = layoutsFor(program) != null

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val name = layoutsFor(program) ?: return false
        val result = MsvcStlApplier(program, StlLayouts.load(name)).apply()
        if (result.replaced + result.filled > 0) {
            report("laid out ${result.replaced + result.filled} std class(es) from $name")
        }
        return true
    }

    private fun layoutsFor(program: Program) = MsvcRuntime.of(program)?.layouts(program.defaultPointerSize)

    companion object {
        const val NAME = "MSVC standard library layouts"
    }
}
