package ghicpp.dissect

import ghicpp.returnsInSlot
import ghicpp.thisArgument
import ghicpp.thisIndex
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidrakt.orThunked

/** The object a call is made on, as the calling function has it. */
sealed interface CalledObject {
    /** What tells the object apart from the caller's others; none for `this`, which there is one of. */
    val id: Int?

    /** The caller's own incoming `this`. */
    data object This : CalledObject {
        override val id: Int? = null
    }

    /**
     * Another object, one a call at [madeAt] returned: [madeBy] that call's callee, with [arg] its first argument
     * where a constant, as `operator new(size)` is.
     */
    data class Returned(override val id: Int, val madeAt: Address, val madeBy: Function?, val arg: Long?) : CalledObject

    /** Another object that the caller has, a local or an argument. */
    data class Local(override val id: Int) : CalledObject
}

/**
 * A call at [at] of [callee], given as its `this` ([thisArgument]) a pointer [offset] bytes into [obj]. With
 * [slot], the pointer is instead the hidden pointer to what the call returns ([returnsInSlot]), which it builds.
 * [returns] is the object its result points into, if any. [next] is the constant address it passes right after
 * `this`, if any, such as the VTT pointer an Itanium base-object structor takes.
 */
data class ObjectCall(
    val at: Address,
    val callee: Function,
    val obj: CalledObject,
    val offset: Long,
    val returns: CalledObject.Returned? = null,
    val slot: Boolean = false,
    val next: Address? = null,
)

/**
 * The calls [this] makes on an object, `this` being what comes in at [thisAt]: each direct call whose
 * callee's `this` argument points into a variable, and each one's result where it points into one.
 */
internal fun HighFunction.objectCalls(thisAt: Address?): List<ObjectCall> {
    val ids = mutableMapOf<Any, CalledObject>()

    // The decompiler may merge what two calls return into one variable, as two `operator new`s into EAX:
    // the call [pointer] comes off tells their objects apart, and only where none does, the variable.
    fun objectOf(pointer: Varnode, root: HighVariable): CalledObject {
        if (PointerInto(root, 0).isThis(thisAt)) return CalledObject.This
        val call = pointer.returnedBy()
            ?: root.instances.firstNotNullOfOrNull { it.def?.takeIf { op -> op.opcode == PcodeOp.CALL } }
        return ids.getOrPut(call ?: root) {
            call?.let {
                CalledObject.Returned(
                    ids.size,
                    it.seqnum.target,
                    directCallee(it),
                    it.takeIf { c -> c.numInputs > 1 }?.getInput(1)?.takeIf { v -> v.isConstant }?.offset,
                )
            } ?: CalledObject.Local(ids.size)
        }
    }
    return pcodeOps.asSequence().flatMap { op ->
        val callee = directCallee(op) ?: return@flatMap emptySequence()
        val returns = op.output?.let { out ->
            out.pointerInto()?.let { objectOf(out, it.root) as? CalledObject.Returned }
        }
        val slot = op.getInput(1).takeIf { callee.returnsInSlot() }
        val next = (callee.thisIndex() + 2).takeIf { it < op.numInputs }
            ?.let { op.getInput(it).constantAddress(function.program) }
        listOfNotNull(op.thisArgument(callee)?.let { it to false }, slot?.let { it to true }).asSequence()
            .mapNotNull { (arg, inSlot) ->
                val obj = arg.pointerInto() ?: return@mapNotNull null
                ObjectCall(
                    op.seqnum.target,
                    callee,
                    objectOf(arg, obj.root),
                    obj.offset,
                    returns,
                    inSlot,
                    next.takeUnless {
                        inSlot
                    },
                )
            }
    }.toList()
}

/** The call [this] pointer is the result of, through copies, casts and constant offsets; null for none. */
private fun Varnode.returnedBy(depth: Int = 0): PcodeOp? {
    val op = def ?: return null
    return when {
        op.opcode == PcodeOp.CALL -> op
        depth >= MAX_TRACE_BACK -> null
        op.opcode in TRACED -> op.getInput(0).returnedBy(depth + 1)
        else -> null
    }
}

private val TRACED = setOf(PcodeOp.CAST, PcodeOp.COPY, PcodeOp.INT_ADD, PcodeOp.PTRSUB, PcodeOp.PTRADD)

private const val MAX_TRACE_BACK = 16

/** The function [op] calls directly, through a thunk to what it thunks, or null for no direct call. */
internal fun HighFunction.directCallee(op: PcodeOp): Function? {
    if (op.opcode != PcodeOp.CALL || op.numInputs < 2) return null
    return function.program.functionManager.getFunctionAt(op.getInput(0).address)?.orThunked
}
