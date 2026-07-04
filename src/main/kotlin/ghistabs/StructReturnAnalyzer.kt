package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.*
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor

const val STRUCT_RETURN_ANALYZER_NAME = "Struct-return ABI (x86 gcc)"

/**
 * gcc/MinGW i386 returns every by-value struct/class through a caller-allocated hidden pointer,
 * but Ghidra's x86gcc cspec register-returns any aggregate ≤8 bytes. So a `std::string` (4-byte)
 * or small `list` return is modelled as an EAX value and the real `this` is shoved into a phantom
 * `in_stack_*` slot. This pass detects such returns — a `Composite` return the cspec did not already
 * force indirect — and re-applies the function with custom storage mirroring what the cspec emits
 * for a large return: a forced-indirect return plus an explicit `__return_storage_ptr__` first
 * argument, so `this` and the formals land at the right offsets.
 *
 * Independent of stabs; keyed only on the x86:LE:32 gcc ABI (on SysV x86-64 small PODs really do
 * return in registers, so this must not run there).
 */
class StructReturnAnalyzer :
    AbstractAnalyzer(
        STRUCT_RETURN_ANALYZER_NAME,
        "Force the hidden return pointer for by-value struct/class returns the x86 gcc cspec register-returns.",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        // After the Stabs Importer (LOW), which sets the composite return types this reads.
        priority = AnalysisPriority.LOW_PRIORITY.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?) = program?.run {
        language.processor.toString() == "x86" &&
            !language.isBigEndian &&
            defaultPointerSize == 4 &&
            compilerSpec.compilerSpecID.idAsString == "gcc"
    } ?: false

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        val fixed = program.functionManager.getFunctions(set, true).count {
            monitor?.checkCancelled()
            needsHiddenReturn(it) && forceHiddenReturn(program, it, log)
        }
        if (fixed > 0) log?.appendMsg(STRUCT_RETURN_ANALYZER_NAME, "forced hidden return pointer on $fixed function(s)")
        return true
    }

    private fun needsHiddenReturn(f: Function) = !f.isThunk &&
        !f.hasCustomVariableStorage() &&
        f.`return`.dataType is Composite &&
        !f.`return`.isForcedIndirect

    private fun forceHiddenReturn(program: Program, f: Function, log: MessageLog?): Boolean = runCatching {
        val rt = f.`return`.dataType
        val model = f.callingConvention ?: program.compilerSpec.defaultCallingConvention
        val formals = f.parameters.filterNot { it.isAutoParameter }
        val thisType = f.parameters.firstOrNull { it.autoParameterType == AutoParameterType.THIS }?.dataType
            ?: program.dataTypeManager.getPointer(VoidDataType.dataType)

        // Lay out the prototype the cspec *would* emit if the return were too big for a register;
        // an oversized dummy forces the HIDDENRET path. The hidden pointer and `this` are always
        // pointer-sized, so the stack offsets match our real (small) return.
        val dummy = ArrayDataType(Undefined1DataType.dataType, 64, 1)
        val proto = (listOf<DataType>(dummy) + formals.map { it.dataType }).toTypedArray()
        val layout = model.getStorageLocations(program, proto, true)

        var fi = 0
        val params = layout.drop(1).map { st ->
            when (st.autoParameterType) {
                AutoParameterType.RETURN_STORAGE_PTR ->
                    ParameterImpl(
                        "__return_storage_ptr__",
                        program.dataTypeManager.getPointer(rt),
                        st.asPlain(program),
                        program,
                        SourceType.ANALYSIS,
                    )

                AutoParameterType.THIS ->
                    ParameterImpl("this", thisType, st.asPlain(program), program, SourceType.ANALYSIS)

                else -> formals[fi++].let {
                    ParameterImpl(it.name, it.dataType, st.asPlain(program), program, SourceType.ANALYSIS)
                }
            }
        }
        // reparentMethod's explicit-`this` under __thiscall leaves a spurious local named `this`;
        // it would collide with our reinstated `this`/`__return_storage_ptr__` params.
        f.localVariables.filter { it.name in RESERVED_PARAM_NAMES }.forEach { f.removeVariable(it) }

        val returnVar = ReturnParameterImpl(rt, layout[0], true, program)
        f.updateFunction(
            f.callingConventionName,
            returnVar,
            params,
            FunctionUpdateType.CUSTOM_STORAGE,
            true,
            SourceType.ANALYSIS,
        )
        true
    }.getOrElse {
        log?.appendMsg(STRUCT_RETURN_ANALYZER_NAME, "failed on ${f.name} @ ${f.entryPoint}: ${it.message}")
        false
    }

    private fun VariableStorage.asPlain(program: Program) = VariableStorage(program, *varnodes)

    private companion object {
        val RESERVED_PARAM_NAMES = setOf("this", "__return_storage_ptr__")
    }
}
