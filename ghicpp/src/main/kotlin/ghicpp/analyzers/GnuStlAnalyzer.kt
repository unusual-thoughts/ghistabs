package ghicpp.analyzers

import ghicpp.stl.DwarfLanguages
import ghicpp.stl.GnuRuntime
import ghicpp.stl.StlApplier
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.report

/**
 * Lays out the standard library classes a program uses from libstdc++ ([GnuRuntime]: imported, or linked
 * statically), off the archive bundled with ghicpp ([StlApplier]): the GNU demangler knows a
 * `std::basic_string<char,…>` method's `this` only as an empty struct. One archive per architecture holds
 * both string ABIs, the C++11 one's classes under `std::__cxx11`.
 *
 * A program with its own debug info (stabs, or DWARF of C++ units) is left alone: that already lays out
 * the library's classes as the compiler that built it did, and the archive's would only stand beside them.
 * DWARF of C and assembler units alone, as glibc's start files bring into a gcc 3 build linked on Debian
 * etch, does not count.
 *
 * After the GNU demangler, which makes those placeholders, and before the class passes.
 */
class GnuStlAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Fill the empty std classes the GNU demangler makes with libstdc++'s layouts, " +
            "for a program that imports libstdc++ or links it statically",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // The demangler analyzers run at DATA_TYPE_PROPOGATION.before().before().before().
        priority = AnalysisPriority.DATA_TYPE_PROPOGATION.before().before()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = archiveFor(program) != null && !hasDebugInfo(program)

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val name = archiveFor(program) ?: return false
        GnuRuntime.ARCHIVES.open(name).use { archive ->
            val result = StlApplier(
                program,
                archive.dataTypeManager,
                GnuRuntime.ARCHIVES.classes(name),
                StlApplier.GNU_ROOTS,
            ).apply()
            val laid = result.replaced + result.filled + result.laid
            if (laid + result.recorded > 0) {
                report("laid out $laid std class(es) from $name.gdt, recorded the bases of ${result.recorded}")
            }
        }
        return true
    }

    private fun archiveFor(program: Program) = GnuRuntime.of(program)?.archive(program.defaultPointerSize)

    companion object {
        const val NAME = "libstdc++ layouts"

        /** Whether [program] has stabs, or DWARF that describes C++ ([DwarfLanguages]). */
        fun hasDebugInfo(program: Program) =
            program.memory.getBlock(".stab") != null || DwarfLanguages.describesCxx(program)
    }
}
