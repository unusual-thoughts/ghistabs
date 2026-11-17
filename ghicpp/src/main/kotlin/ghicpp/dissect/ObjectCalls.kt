package ghicpp.dissect

import ghicpp.thisArgument
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp

/** The object a call is made on, as the calling function has it. */
sealed interface CalledObject {
    /** The caller's own incoming `this`. */
    data object This : CalledObject

    /**
     * Another object, [id] telling it apart from the caller's others: one a call at [madeAt] returned, [madeBy]
     * that call's callee, with [size] its first argument where a constant, as `operator new(size)` is; or one the
     * caller has otherwise, a local or an argument, with none of those.
     */
    data class Other(val id: Int, val madeAt: Address? = null, val madeBy: Function? = null, val size: Long? = null) :
        CalledObject
}

/**
 * A call at [at] of [callee], given as its `this` ([thisArgument]) a pointer [offset] bytes into [obj];
 * [returns], the object its result points into, where it points into one.
 */
data class ObjectCall(
    val at: Address,
    val callee: Function,
    val obj: CalledObject,
    val offset: Long,
    val returns: CalledObject.Other? = null,
)

/**
 * The calls [this] makes on an object, `this` being what comes in at [thisAt]: each direct call whose
 * callee's `this` argument points into a variable, and each one's result where it points into one.
 */
internal fun HighFunction.objectCalls(thisAt: Address?): List<ObjectCall> {
    val ids = mutableMapOf<HighVariable, CalledObject>()
    fun objectOf(root: HighVariable): CalledObject = ids.getOrPut(root) {
        if (PointerInto(root, 0).isThis(thisAt)) return@getOrPut CalledObject.This
        val made = root.instances.firstNotNullOfOrNull { it.def?.takeIf { op -> op.opcode == PcodeOp.CALL } }
        CalledObject.Other(
            ids.size,
            made?.seqnum?.target,
            made?.let { directCallee(it) },
            made?.takeIf { it.numInputs > 1 }?.getInput(1)?.takeIf { it.isConstant }?.offset,
        )
    }
    return pcodeOps.asSequence().mapNotNull { op ->
        val callee = directCallee(op) ?: return@mapNotNull null
        val obj = op.thisArgument(callee)?.pointerInto() ?: return@mapNotNull null
        val returns = op.output?.pointerInto()?.let { objectOf(it.root) as? CalledObject.Other }
        ObjectCall(op.seqnum.target, callee, objectOf(obj.root), obj.offset, returns)
    }.toList()
}

/** The function [op] calls directly, through a thunk to what it thunks, or null for no direct call. */
internal fun HighFunction.directCallee(op: PcodeOp): Function? {
    if (op.opcode != PcodeOp.CALL || op.numInputs < 2) return null
    val f = function.program.functionManager.getFunctionAt(op.getInput(0).address) ?: return null
    return f.getThunkedFunction(true) ?: f
}
