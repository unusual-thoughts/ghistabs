package ghicpp

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DoubleDataType
import ghidra.program.model.data.Float10DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.lang.PrototypeModel
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
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
 * Not where `__thiscall` would return the value elsewhere ([keepsReturn]). Returns whether it changed anything.
 */
fun Function.fastcallToThiscall(): Boolean {
    if (callingConventionName != FASTCALL) return false
    val model = program.functionManager.getCallingConvention(THISCALL) ?: return false
    val (ecx, edx) = listOf("ECX", "EDX").map { program.language.getRegister(it) ?: return false }
    if (parameters.any { it.register?.baseRegister == edx.baseRegister }) return false
    val returned = returnTypeUnder(model) ?: return false
    val params = parameters.toList()
    val rest = if (params.firstOrNull()?.register?.baseRegister == ecx.baseRegister) params.drop(1) else params
    return runCatching {
        updateFunction(
            THISCALL,
            ReturnParameterImpl(returned, program),
            rest.map { ParameterImpl(it.name, it.dataType, program, it.source) },
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true,
            signatureSource,
        )
    }.isSuccess
}

/**
 * The return type to give this function under [model]'s own storage, or null where [model] would return it
 * somewhere else than it now is: a `float10` in ST0, which a `__thiscall` with dynamic storage returns through
 * a hidden pointer, its aligned size past ST0's. Under MSVC a `long double` is a `double`, so there a `float10`
 * in ST0 is the `double` it was, which `__thiscall` returns in ST0 too.
 */
private fun Function.returnTypeUnder(model: PrototypeModel): DataType? {
    val now = `return`
    val type = if (now.dataType is Float10DataType && program.compilerSpec.compilerSpecID.idAsString == MSVC) {
        DoubleDataType.dataType
    } else {
        now.dataType
    }
    if (now.variableStorage.isVoidStorage || now.variableStorage.isUnassignedStorage) return type
    val then = model.getStorageLocations(program, arrayOf(type), false)[0]
    val keepsReturn = !then.isForcedIndirect && then.firstVarnode?.address == now.variableStorage.firstVarnode?.address
    return type.takeIf { keepsReturn }
}

/**
 * Gives a method back the auto-`this` Ghidra's "Decompiler Parameter ID" froze out: it commits a decompiled
 * signature, `this` as an ordinary parameter, in custom storage whenever that storage disagrees with the
 * convention's, and custom storage is what suppresses the auto-parameter. Re-applying the formals with dynamic
 * storage drops it, and Ghidra re-derives `this` from the class. A method it committed with no parameter at all,
 * having seen `this` go unread, gets `this` back the same way. Whether it changed anything; throws where
 * Ghidra refuses the signature.
 */
fun Function.restoreThisParam(): Boolean {
    // Custom storage means no auto-params, so a `this` among the parameters is a stored one: the shape to undo.
    // So is no parameter at all, where an analysis saw `this` go unread, as in a `what()` returning a literal.
    val storedThis = parameters.any { it.name == Function.THIS_PARAM_NAME }
    val unreadThis = parameterCount == 0 && !signatureSource.isHigherPriorityThan(SourceType.ANALYSIS)
    val frozen = isMethod && hasCustomVariableStorage() && callingConvention?.hasThisPointer() == true &&
        (storedThis || unreadThis)
    if (!frozen) return false
    // Dynamic storage re-derives the return's too: not where that moves it ([returnTypeUnder]).
    val returned = callingConvention?.let { returnTypeUnder(it) } ?: return false
    // Ours to drop: `updateFunction` strips an explicit `this` only when it is pointer-typed. Copies, not the
    // live parameters: `updateFunction` clears the names off those before reading the list back, so passing
    // them in loses the name and source it is being asked to keep.
    updateFunction(
        callingConventionName,
        ReturnParameterImpl(returned, program),
        parameters.filterNot { it.isInjected }.map { ParameterImpl(it.name, it.dataType, program, it.source) },
        Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
        true,
        signatureSource,
    )
    return true
}

/**
 * Gives a function that takes `this` but no convention saying so the `__thiscall` that does, where that only
 * names its first argument: its convention unknown, the default or the compiler's default, set by an analysis,
 * and `__thiscall` taking `this` where that convention takes the first argument, its return where it is
 * ([returnTypeUnder]). Under x86 gcc, whose `__thiscall` takes `this` on the stack as `__cdecl` takes its
 * first argument; not under MSVC, whose takes it in ECX ([fastcallToThiscall] covers that). Only for a
 * function known to take `this`: a static member function sits in its class too. Whether it changed anything.
 */
fun Function.thiscallFromFirstArgument(): Boolean {
    val fm = program.functionManager
    val thiscall = fm.getCallingConvention(THISCALL) ?: return false
    val defaultModel = program.compilerSpec.defaultCallingConvention
    val current = when (callingConventionName) {
        Function.UNKNOWN_CALLING_CONVENTION_STRING, Function.DEFAULT_CALLING_CONVENTION_STRING -> defaultModel
        defaultModel.name -> defaultModel
        else -> return false
    }
    if (signatureSource.isHigherPriorityThan(SourceType.ANALYSIS)) return false
    val pointer = PointerDataType(program.dataTypeManager)
    val thisAt = thiscall.getArgLocation(0, null, pointer, program)
    if (current.getArgLocation(0, null, pointer, program) != thisAt) return false
    val returned = returnTypeUnder(thiscall) ?: return false
    val params = parameters.filterNot { it.isAutoParameter }
    val rest = if (params.firstOrNull()?.variableStorage == thisAt) params.drop(1) else params
    return runCatching {
        updateFunction(
            THISCALL,
            ReturnParameterImpl(returned, program),
            rest.map { ParameterImpl(it.name, it.dataType, program, it.source) },
            Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true,
            signatureSource,
        )
    }.isSuccess
}

/**
 * A method's convention as `this` makes it: [fastcallToThiscall], then [restoreThisParam], and where the
 * caller knows it [takesThis] (a class pass placed it: a virtual function, a structor, a method guessed off its
 * callers), [thiscallFromFirstArgument]. What every function that lands in a class goes through, from the
 * analyzer ([ghicpp.analyzers.MethodConventionAnalyzer]) or a class pass placing it. Whether it changed
 * anything; throws where Ghidra refuses the signature.
 */
fun Function.fixMethodConvention(takesThis: Boolean = false): Boolean =
    fastcallToThiscall() or (takesThis && thiscallFromFirstArgument()) or restoreThisParam()

private const val FASTCALL = CompilerSpec.CALLING_CONVENTION_fastcall
private const val THISCALL = CompilerSpec.CALLING_CONVENTION_thiscall
private const val MSVC = "windows"

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
