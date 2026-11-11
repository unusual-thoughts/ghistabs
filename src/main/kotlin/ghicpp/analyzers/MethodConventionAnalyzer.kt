package ghicpp.analyzers

import ghicpp.fixMethodConvention
import ghicpp.recover.ClassPassTags
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.report
import ghistabs.isMethod

/**
 * Each method's calling convention as `this` makes it ([fixMethodConvention]): an x86 `__fastcall` that takes
 * nothing in EDX becomes the `__thiscall` it is, and a method Ghidra's "Decompiler Parameter ID" committed in
 * custom storage gets its auto-`this` back. One a class pass placed ([ClassPassTags.METHOD]) is known to take
 * `this`, so a default convention becomes `__thiscall` too, as the pass makes it.
 *
 * On the functions already in a class when they are added: the debug info's, the demangler's. The class passes,
 * which run later, give each function they place in a class the same treatment, its virtual functions included.
 * Any C++ program; re-run it alone after a Decompiler Parameter ID that froze methods again.
 */
class MethodConventionAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Make each class method's calling convention take `this`: a __fastcall with nothing in EDX becomes " +
            "__thiscall, and a method committed with custom storage gets the convention's `this` back.",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        // After Decompiler Parameter ID (DATA_TYPE_PROPOGATION+2), whose commit this undoes, and after the
        // Stabs Importer (LOW), so a restored `this` reaches an imported class type.
        priority = AnalysisPriority.LOW_PRIORITY.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        val methods = program.functionManager.getFunctions(set, true).filter { it.isMethod }
        monitor.initialize(methods.size.toLong(), "Fixing method conventions")
        val fixed = methods.count { f ->
            monitor.increment()
            runCatching { f.fixMethodConvention(takesThis = f.tags.any { it.name == ClassPassTags.METHOD }) }
                .onFailure { log.appendMsg(NAME, "failed on ${f.name} @${f.entryPoint}: ${it.message}") }
                .getOrDefault(false)
        }
        if (fixed > 0) report("fixed the convention of $fixed method(s)")
        return true
    }

    companion object {
        const val NAME = "C++ method calling convention"
    }
}
