package ghicpp.fixup

import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor

/**
 * Whether the instruction at [addr] is inside another function's body only because that function jumps there, as
 * it does when a compiler turns a tail call into a jump to the next function: unconditional jumps reach it, and
 * nothing else does, neither a fall-through from the instruction before it, nor a conditional or computed jump.
 * A switch's cases and a loop's head are reached some other way.
 */
fun Program.isTailJumpTarget(addr: Address): Boolean {
    val fn = functionManager.getFunctionContaining(addr) ?: return false
    if (fn.entryPoint == addr || listing.getInstructionAt(addr) == null) return false
    if (listing.getInstructionBefore(addr)?.fallThrough == addr) return false
    val flows = referenceManager.getReferencesTo(addr).filter { it.referenceType.isFlow }
    return flows.isNotEmpty() && flows.all { it.referenceType == RefType.UNCONDITIONAL_JUMP }
}

/**
 * Makes the code at [addr] that another function only jumps to ([isTailJumpTarget]) a function of its own, and
 * takes it out of that function's body. Null where [addr] is no such code, or where the code it flows to reaches
 * back into the other function's entry.
 */
fun Program.splitOffTailJumpTarget(addr: Address): Function? {
    if (!isTailJumpTarget(addr)) return null
    val outer = functionManager.getFunctionContaining(addr) ?: return null
    val body = CreateFunctionCmd.getFunctionBody(this, addr, TaskMonitor.DUMMY)
        ?.intersect(outer.body)
        ?.takeUnless { it.isEmpty || it.contains(outer.entryPoint) }
        ?: return null
    outer.setBody(outer.body.subtract(body))
    return functionManager.createFunction(null, addr, body, SourceType.ANALYSIS)
}
