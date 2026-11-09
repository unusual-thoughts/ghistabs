package ghicpp

import ghidra.program.model.address.Address
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghistabs.isInjected
import ghistabs.isMethod

/** How long a class pass waits on the decompiler for one function. */
const val DECOMPILE_TIMEOUT_SECONDS = 30

/** Each of these classes' vtables, by its address point: the class it serves and where its vptr sits in it. */
fun Collection<ClassDecl>.vptrTables(program: Program): Map<Address, Pair<ClassDecl, Long>> = flatMap { cls ->
    cls.vftables.mapNotNull { r -> r.vfptrOffset(program)?.let { r.addressPoint to (cls to it) } }
}.toMap()

/** Where `this` comes in: ECX under x86 `__thiscall`, the first argument register elsewhere. */
fun Program.thisStorage(): Address? {
    val model = functionManager.getCallingConvention(THISCALL) ?: compilerSpec.defaultCallingConvention
    return model.getArgLocation(0, null, PointerDataType(dataTypeManager), this).firstVarnode?.address
}

/**
 * Turns a method's x86 `__fastcall` with nothing in EDX into the `__thiscall` it really is, the ECX
 * parameter becoming `this`. Ghidra picks `__fastcall` when `this` is the only register argument.
 * Returns whether it changed anything.
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

/**
 * Gives a method back the auto-`this` Ghidra's "Decompiler Parameter ID" froze out: it commits a decompiled
 * signature, `this` as an ordinary parameter, in custom storage whenever that storage disagrees with the
 * convention's, and custom storage is what suppresses the auto-parameter. Re-applying the formals with dynamic
 * storage drops it, and Ghidra re-derives `this` from the class. Whether it changed anything; throws where
 * Ghidra refuses the signature.
 */
fun Function.restoreThisParam(): Boolean {
    // Custom storage means no auto-params, so a `this` among the parameters is a stored one: the shape to undo.
    val frozen = isMethod && hasCustomVariableStorage() && callingConvention?.hasThisPointer() == true &&
        parameters.any { it.name == Function.THIS_PARAM_NAME }
    if (!frozen) return false
    // Ours to drop: `updateFunction` strips an explicit `this` only when it is pointer-typed. Copies, not the
    // live parameters: `updateFunction` clears the names off those before reading the list back, so passing
    // them in loses the name and source it is being asked to keep.
    replaceParameters(
        parameters.filterNot { it.isInjected }.map { ParameterImpl(it.name, it.dataType, program, it.source) },
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        true,
        signatureSource,
    )
    return true
}

/**
 * A method's convention as `this` makes it: [fastcallToThiscall], then [restoreThisParam]. What every function
 * that lands in a class goes through, from the analyzer ([ghicpp.entrypoints.MethodConventionAnalyzer]) or a
 * class pass placing it. Whether it changed anything; throws where Ghidra refuses the signature.
 */
fun Function.fixMethodConvention(): Boolean = fastcallToThiscall() or restoreThisParam()

private const val FASTCALL = CompilerSpec.CALLING_CONVENTION_fastcall
private const val THISCALL = CompilerSpec.CALLING_CONVENTION_thiscall

/**
 * A pointer as the variable it points into ([root]) and how far past it ([offset]). The decompiler merges a
 * variable's copies and phis into one [HighVariable], so [root] is the same however the pointer got there.
 */
data class PointerInto(val root: HighVariable, val offset: Long) {
    /** Whether [root] is the function's incoming `this`, which comes in at [thisStorage]. */
    fun isThis(thisStorage: Address?) = root.instances.any { it.isInput && it.address == thisStorage }
}

/** Traces a decompiled pointer back through casts and constant adds to the variable it points into. */
fun Varnode.pointerInto(offset: Long = 0, depth: Int = 0): PointerInto? = when (
    (def?.opcode)?.takeIf { depth < MAX_TRACE }
) {
    PcodeOp.CAST -> def.getInput(0).pointerInto(offset, depth + 1)

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

    else -> null
} ?: high?.let { PointerInto(it, offset) }

private const val MAX_TRACE = 16

/** The class a function storing [classes]' vtables builds or destroys: the one the others are bases of, or null. */
fun storedClass(classes: Set<ClassDecl>): ClassDecl? =
    classes.singleOrNull { c -> classes.all { it == c || c.derivesFrom(it) } }
