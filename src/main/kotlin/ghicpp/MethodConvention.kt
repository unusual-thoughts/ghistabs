package ghicpp

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DoubleDataType
import ghidra.program.model.data.Float10DataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.lang.PrototypeModel
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Parameter
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
import ghistabs.isInjected
import ghistabs.isMethod

/** Where `this` comes in: ECX under x86 `__thiscall`, the first argument register elsewhere. */
fun Program.thisStorage(): Address? {
    val model = functionManager.getCallingConvention(THISCALL) ?: compilerSpec.defaultCallingConvention
    return model.getArgLocation(0, null, PointerDataType(dataTypeManager), this).firstVarnode?.address
}

/** Where [this]'s [i]th argument comes in, a pointer, under its calling convention or the program's default. */
fun Function.argumentAt(i: Int): Address? = (callingConvention ?: program.compilerSpec.defaultCallingConvention)
    .getArgLocation(i, null, PointerDataType(program.dataTypeManager), program).firstVarnode?.address

/**
 * Whether [this]'s first argument comes in at [thisStorage], where a method's `this` does: not a `cdecl`
 * function's, which `strcpy(this->name, ...)` is passed. Under `__thiscall` or `__fastcall` with MSVC, and under
 * `__cdecl` too with MinGW gcc before 4.7, which passes `this` on the stack.
 */
fun Function.takesThisAt(thisStorage: Address?) = !isExternal && thisStorage != null && argumentAt(0) == thisStorage

/**
 * Which of its arguments is `this`: the second where a `__cdecl` function pops one word, which is gcc's
 * hidden pointer for a class returned in memory, and the first otherwise.
 */
fun Function.thisIndex() = if (callingConventionName == CDECL && stackPurgeSize == program.defaultPointerSize) 1 else 0

/** The argument a call passes [callee] as its `this`. */
fun PcodeOp.thisArgument(callee: Function): Varnode? = callee.thisIndex().let { i ->
    if (numInputs > i + 1) getInput(i + 1) else null
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
 * Gives a function that takes `this` but no convention saying so the `__thiscall` that does: its convention
 * unknown, the default or the compiler's default, set by an analysis, and its return where `__thiscall` puts it
 * ([returnTypeUnder]). Under x86 gcc, whose `__thiscall` takes `this` on the stack as `__cdecl` takes its
 * first argument, that argument becomes `this`. Under MSVC, whose `__thiscall` takes `this` in ECX, a
 * `__stdcall` an analysis committed becomes it with its stack arguments where they are, both popping them:
 * what Ghidra makes of a method that never reads `this` ([fastcallToThiscall] covers one that does). Not one
 * with no signature yet, as a class pass makes a slot's target: Decompiler Parameter ID may find it reads ECX
 * and EDX, and [ghicpp.analyzers.MethodConventionAnalyzer] takes it from there. Only for a function known to
 * take `this`: a static member function sits in its class too. Whether it changed anything.
 */
fun Function.thiscallFromDefaultConvention(): Boolean {
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
    val params = parameters.filterNot { it.isAutoParameter }
    val rest = when {
        current.getArgLocation(0, null, pointer, program) == thisAt ->
            if (params.firstOrNull()?.variableStorage == thisAt) params.drop(1) else params

        // An analysis's signature only: a function just made has none yet, and its registers may yet show EDX.
        current.name == STDCALL && thisAt.isRegisterStorage && signatureSource == SourceType.ANALYSIS &&
            params.keepStorageUnder(thiscall, program) -> params

        else -> return false
    }
    val returned = returnTypeUnder(thiscall) ?: return false
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

/** Whether these parameters, after a `this`, sit where [model] puts them, as a `__stdcall`'s stack ones do. */
private fun List<Parameter>.keepStorageUnder(model: PrototypeModel, program: Program): Boolean {
    val types = arrayOf<DataType>(VoidDataType.dataType, PointerDataType(program.dataTypeManager)) +
        map { it.dataType }
    val storage = model.getStorageLocations(program, types, false).drop(2)
    return zip(storage).all { (param, at) -> param.variableStorage == at }
}

/**
 * A method's convention as `this` makes it: [fastcallToThiscall], then [restoreThisParam], and where the
 * caller knows it [takesThis] (a class pass placed it: a virtual function, a structor, a method guessed off its
 * callers), [thiscallFromDefaultConvention]. What every function that lands in a class goes through, from the
 * analyzer ([ghicpp.analyzers.MethodConventionAnalyzer]) or a class pass placing it. Whether it changed
 * anything; throws where Ghidra refuses the signature.
 */
fun Function.fixMethodConvention(takesThis: Boolean = false): Boolean =
    fastcallToThiscall() or (takesThis && thiscallFromDefaultConvention()) or restoreThisParam()

private const val FASTCALL = CompilerSpec.CALLING_CONVENTION_fastcall
private const val STDCALL = CompilerSpec.CALLING_CONVENTION_stdcall
private const val THISCALL = CompilerSpec.CALLING_CONVENTION_thiscall
private const val CDECL = CompilerSpec.CALLING_CONVENTION_cdecl
private const val MSVC = "windows"
