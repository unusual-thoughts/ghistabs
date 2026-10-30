package ghistabs.cpp.recover

import ghidra.program.model.address.Address
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

/** Where `this` comes in: ECX under x86 `__thiscall`, the first argument register elsewhere. */
fun Program.thisStorage(): Address? {
    val model = functionManager.getCallingConvention(THISCALL) ?: compilerSpec.defaultCallingConvention
    return model.getArgLocation(0, null, PointerDataType(dataTypeManager), this).firstVarnode?.address
}

/**
 * Make an x86 `__fastcall` that takes nothing in EDX the `__thiscall` it may as well be, and is, once it
 * is known to be a method: both take the first argument in ECX and the rest on the stack, popped by the
 * callee, and only `__fastcall` takes a second in EDX. Ghidra picks `__fastcall` for a method whose
 * only register argument is `this`. The ECX parameter becomes the `this` the convention adds. Whether
 * it changed it.
 */
fun Function.fastcallToThiscall(): Boolean {
    if (callingConventionName != FASTCALL) return false
    if (program.functionManager.getCallingConvention(THISCALL) == null) return false
    val (ecx, edx) = listOf("ECX", "EDX").map { program.language.getRegister(it) ?: return false }
    if (parameters.any { it.register?.baseRegister == edx.baseRegister }) return false
    val params = parameters.toList()
    val rest = if (params.firstOrNull()?.register?.baseRegister == ecx.baseRegister) params.drop(1) else params
    return runCatching {
        updateFunction(
            THISCALL,
            `return`,
            rest.map { ParameterImpl(it.name, it.dataType, program, it.source) },
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true,
            signatureSource,
        )
    }.isSuccess
}

private const val FASTCALL = CompilerSpec.CALLING_CONVENTION_fastcall
private const val THISCALL = CompilerSpec.CALLING_CONVENTION_thiscall

/** A pointer as the value it points into ([root]) and how far past it ([offset]). */
data class PointerInto(val root: Varnode, val offset: Long) {
    /** Whether [root] is the function's incoming `this`, which comes in at [thisStorage]. */
    fun isThis(thisStorage: Address?) = root.isInput && root.address == thisStorage
}

/**
 * Trace a decompiled pointer back through copies, casts and constant adds, and through a phi whose
 * other inputs are all null, as a pointer from `new` checked before its constructor runs is.
 */
fun Varnode.pointerInto(offset: Long = 0, depth: Int = 0): PointerInto = when (
    (def?.opcode)?.takeIf { depth < MAX_TRACE }
) {
    PcodeOp.COPY, PcodeOp.CAST -> def.getInput(0).pointerInto(offset, depth + 1)

    PcodeOp.INT_ADD, PcodeOp.PTRSUB -> def.getInput(1).takeIf { it.isConstant }?.let { by ->
        def.getInput(0).pointerInto(offset + by.offset, depth + 1)
    }

    PcodeOp.PTRADD -> {
        val (index, size) = def.getInput(1) to def.getInput(2)
        when {
            !index.isConstant || !size.isConstant -> null
            else -> def.getInput(0).pointerInto(offset + index.offset * size.offset, depth + 1)
        }
    }

    PcodeOp.MULTIEQUAL -> def.inputs.filterNot { it.isConstant && it.offset == 0L }.singleOrNull()
        ?.pointerInto(offset, depth + 1)

    else -> null
} ?: PointerInto(this, offset)

private const val MAX_TRACE = 16
