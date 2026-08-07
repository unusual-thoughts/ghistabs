package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.block.CodeBlockReference
import ghidra.program.model.block.SimpleBlockModel
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

const val NO_RETURN_ANALYZER_NAME = "Non-returning functions (reachability)"

/**
 * Mark a function whose every path runs into a call to a function that cannot return.
 *
 * unpackfile's `error()` calls `exit` and never comes back, but nothing marks it, so every caller
 * decompiles with the unreachable tail still attached — which is where the `goto LAB_…` soup and the
 * out-of-source-order branches the render then has to lay out come from.
 *
 * Ghidra can already decide this: [ghidra.app.plugin.core.analysis.FindNoReturnFunctionsAnalyzer]'s
 * `targetOnlyCallsNoReturn` is this walk. But it is only the *fallback* for a target whose call sites
 * showed damage — garbage decoded after the call — and `error()`'s call sites decode perfectly
 * cleanly, so it is never examined. (It also runs at `DISASSEMBLY.after().after()`, before
 * [StabsAnalyzer] at `LOW_PRIORITY` has created the functions it would examine.) Hence the same walk,
 * ungated, as a FUNCTION_ANALYZER — the trigger wanted is a new function being defined, by stabs or
 * by anything else.
 *
 * **Conservatism is the whole design.** A path may end *only* at a known non-returning call; anything
 * the CFG cannot resolve — a null block, a block with no destinations, an unrecovered computed jump —
 * means "assume it returns". An earlier instruction-walk version dead-ended on libstdc++'s switch
 * tables and read that as proof, marking `strtold`, `do_put`, `_S_pad` and twenty-odd other locale
 * functions that plainly return; Ghidra then cleared the code after their call sites as unreachable.
 * Working over [SimpleBlockModel] rather than a hand-rolled instruction walk is what makes the
 * unresolved cases visible as such.
 *
 * One edge needs help, and it is the reason Ghidra's own walk cannot simply be reused here: the
 * fall-through past a non-returning call. `setNoFallThru` repair has already removed it by the time
 * *its* walk runs and has not by the time ours does, so the model still offers it — and it points at
 * whatever the linker placed next, which is no part of this function. unpackfile's `error` ends at
 * `call exit` with 0x401300 (inline string data) behind it; follow that edge and `getCodeBlockAt`
 * returns null, which this reads as "assume it returns". Elsewhere the same edge runs into an
 * unrelated function and finds its `ret`. Either way the answer is wrong, so the edge is dropped
 * explicitly; every other one is the model's.
 * Ghidra's terminal-tail-call guard is kept exactly as written, and is load-bearing: without it
 * `std::string::assign`/`replace`, which end `jmp <other overload>` with their only other exit a
 * `__throw_out_of_range` call, read as never returning.
 *
 * Independent of stabs, but scheduled after the importer: on a stripped binary most of these functions
 * do not exist until it has run.
 */
class NoReturnAnalyzer :
    AbstractAnalyzer(
        NO_RETURN_ANALYZER_NAME,
        "Mark functions whose every path ends in a call to a non-returning function.",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        val marked = markNoReturn(program, set, monitor ?: TaskMonitor.DUMMY)
        if (marked.isNotEmpty()) {
            log?.appendMsg(NO_RETURN_ANALYZER_NAME, "marked ${marked.size} function(s) non-returning")
        }
        return true
    }
}

/**
 * Mark the non-returning functions reachable from [set], returning those newly marked. Marking one
 * can settle a caller that was undecided (`error` → `exit` → its own callers), so each success
 * re-queues that function's callers; the fixed point terminates because marking is one-way and only a
 * new mark enqueues anything. Re-running is therefore idempotent and cheap. See [NoReturnAnalyzer].
 */
fun markNoReturn(program: Program, set: AddressSetView?, monitor: TaskMonitor = TaskMonitor.DUMMY): List<Function> {
    val funMgr = program.functionManager
    val model = SimpleBlockModel(program)

    fun noReturnAt(addr: Address) = funMgr.getFunctionAt(addr)?.hasNoReturn() == true

    /** An edge that leaves the CFG for good — the only way a path is allowed to end. */
    fun ends(d: CodeBlockReference) = (d.flowType.isCall || d.flowType.isJump) && noReturnAt(d.destinationAddress)

    /** Control handed to another function that will hand it back — a call, or a jump to a function. */
    fun isTailCall(d: CodeBlockReference) =
        d.flowType.isCall || (d.flowType.isJump && funMgr.getFunctionAt(d.destinationAddress) != null)

    /** Ghidra's `targetOnlyCallsNoReturn`, minus the fall-through past a call that cannot return. */
    fun cannotReturn(func: Function): Boolean {
        val todo = ArrayDeque(listOf(func.entryPoint))
        val seen = mutableSetOf<Address>()
        var hitNoReturn = false
        while (todo.isNotEmpty()) {
            monitor.checkCancelled()
            val at = todo.removeLast()
            if (!seen.add(at)) continue
            val block = model.getCodeBlockAt(at, monitor) ?: return false
            // A reachable `ret` settles it; a CALL_TERMINATOR still has the callee left to check.
            if (block.flowType.isTerminal && !block.flowType.isCall) return false
            val dests = block.getDestinations(monitor)
                .let { i -> generateSequence { if (i.hasNext()) i.next() else null } }.toList()
            // No destinations at all is unrecovered flow — a computed jump, most often — not proof.
            if (dests.isEmpty()) return false
            // A terminal block that tail-calls a function which does return, returns through it.
            // `std::string::assign`/`replace` end `jmp <other overload>` with their only other exit a
            // `__throw_out_of_range` call, so without this they read as never returning.
            if (block.flowType.isTerminal && dests.any { !ends(it) && isTailCall(it) }) return false
            hitNoReturn = hitNoReturn || dests.any(::ends)

            // Only a *call* leaves a fall-through behind; a conditional jump to a non-returning
            // target still falls through to live code.
            val deadFallThrough = dests.any { it.flowType.isCall && ends(it) }
            dests.filterNot {
                ends(it) ||
                    it.flowType.isCall ||
                    it.flowType.isIndirect ||
                    (deadFallThrough && it.flowType.isFallthrough)
            }.mapTo(todo, CodeBlockReference::getDestinationAddress)
        }
        return hitNoReturn
    }

    val todo = ArrayDeque(funMgr.getFunctions(set, true).toList())
    return buildList {
        while (todo.isNotEmpty()) {
            val func = todo.removeFirst()
            if (func.hasNoReturn() || func.isThunk || func.isExternal || !cannotReturn(func)) continue
            func.setNoReturn(true)
            add(func)
            func.getCallingFunctions(monitor).toCollection(todo)
        }
    }
}
