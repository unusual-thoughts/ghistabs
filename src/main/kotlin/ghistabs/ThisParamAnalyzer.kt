package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

const val THIS_PARAM_ANALYZER_NAME = "Class-method this-pointer"

/**
 * Give class methods back the auto-`this` Ghidra's "Decompiler Parameter ID" analyzer froze out: it
 * commits a decompiled signature — this-pointer as an ordinary parameter — in `CUSTOM_STORAGE`
 * whenever that storage disagrees with the convention's, and custom storage is exactly what suppresses
 * the auto-param, leaving the decompiler's `undefined4` guess as the signature. Re-applying the
 * formals with dynamic storage drops it; Ghidra then re-derives `this` from the class structure.
 *
 * Independent of stabs — the damage is the decompiler's, and lands on any C++ program Ghidra
 * analyzes — so this is an analyzer rather than an import pass: it then also runs on binaries that
 * carry no stabs at all, and can be re-run alone after a Decompiler Parameter ID that re-froze them.
 */
class ThisParamAnalyzer :
    AbstractAnalyzer(
        THIS_PARAM_ANALYZER_NAME,
        "Restore the convention's `this` on class methods committed with custom storage.",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        // After Decompiler Parameter ID (DATA_TYPE_PROPOGATION+2), whose commit this undoes, and
        // after the Stabs Importer (LOW), so a restored `this` reaches an imported class type.
        priority = AnalysisPriority.LOW_PRIORITY.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = program.compilerSpec.callingConventions.any { it.hasThisPointer() }

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        val frozen = program.functionManager.getFunctions(set, true)
            .filter { it.isMethod && it.hasCustomVariableStorage() }
            .filter { it.callingConvention?.hasThisPointer() == true }
            // Custom storage means no auto-params, so this `this` is a stored one — the shape to undo.
            .filter { f -> f.parameters.any { it.name == Function.THIS_PARAM_NAME } }
        monitor?.checkCancelled()

        frozen.count { it.redoStorage(log) }.takeIf { it > 0 }?.let { restored ->
            log?.appendMsg(THIS_PARAM_ANALYZER_NAME, "restored `this` on $restored method(s)")
        }
        return true
    }

    // Ours to drop: `updateFunction` strips an explicit `this` only when it is pointer-typed. Copies,
    // not the live parameters: `updateFunction` clears the names off those before reading the list
    // back, so passing them in loses the name and source it is being asked to keep.
    private fun Function.redoStorage(log: MessageLog?) = runCatching {
        replaceParameters(
            parameters.filterNot { it.isInjected }.map { ParameterImpl(it.name, it.dataType, program, it.source) },
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true,
            signatureSource,
        )
    }.onFailure {
        log?.appendMsg(THIS_PARAM_ANALYZER_NAME, "failed on $name @$entryPoint: ${it.message}")
    }.isSuccess
}
