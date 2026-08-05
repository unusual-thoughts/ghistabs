package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

const val NO_RETURN_ANALYZER_NAME = "Non-returning functions (reachability)"

/**
 * Mark every function whose every path runs into a non-returning call.
 *
 * Ghidra can already decide this — `FindNoReturnFunctionsAnalyzer.targetOnlyCallsNoReturn` is the
 * same walk — but never gets the chance. That method is only the *fallback* for a target whose call
 * sites showed damage below `evidenceThresholdFunctions`; `detectNoReturn` skips any call
 * instruction failing `checkNonReturningIndicators` before ever reaching it. Damage means garbage
 * decoded after a call, so a function with clean call sites is skipped and never examined —
 * unpackfile's `error()`, which calls `exit` and cannot return, is exactly that. Left unmarked,
 * every caller decompiles with the unreachable tail still attached, which is where the `goto LAB_…`
 * soup and out-of-source-order branches come from.
 *
 * The same walk, then, ungated — but over instructions rather than `SimpleBlockModel` blocks.
 * Ghidra's version runs *after* its own `setNoFallThru` repair has cleared the fall-through edge past
 * a non-returning call; before that, the block model still hands back the fall-through block holding
 * the dead `ret` and the walk concludes the function returns. Measured on unpackfile: the
 * block-model form left `goto`/`LAB_` at 11 where this one takes it to 2. Skipping the fall-through
 * at such a call is precisely the edge that repair would have removed.
 *
 * Reachability is the necessary part, not "has no `ret`" — gcc leaves one behind as dead code, and
 * `error` has 13 instructions with a `ret` among them after the `exit`.
 *
 * Independent of stabs, but scheduled after the Stabs Importer: on a stripped binary most of these
 * functions do not exist until it has run.
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
        val marked = markNoReturn(program, monitor)
        if (marked > 0) log?.appendMsg(NO_RETURN_ANALYZER_NAME, "marked $marked function(s) non-returning")
        return true
    }
}

/**
 * Mark non-returning functions in [program], iterating to a fixed point so a chain (`error` → `exit`)
 * resolves however deep it goes. Returns how many were newly marked. See [NoReturnAnalyzer].
 */
fun markNoReturn(program: Program, monitor: TaskMonitor? = null): Int {
    val listing = program.listing
    val funMgr = program.functionManager

    fun endsPath(i: Instruction) = i.flowType.isCall && i.flows.any { funMgr.getFunctionAt(it)?.hasNoReturn() == true }

    fun canReturn(func: Function): Boolean {
        val seen = mutableSetOf<Address>()
        val work = ArrayDeque(listOfNotNull(listing.getInstructionAt(func.entryPoint)))
        while (work.isNotEmpty()) {
            val i = work.removeFirst()
            if (!seen.add(i.address)) continue
            if (i.flowType.isTerminal) return true
            // A jump out of the body is a tail call: it returns through the callee.
            if (i.flowType.isJump && i.flows.any { !func.body.contains(it) }) return true
            if (!endsPath(i)) i.fallThrough?.let { listing.getInstructionAt(it) }?.let { work += it }
            if (i.flowType.isJump) i.flows.mapNotNullTo(work) { listing.getInstructionAt(it) }
        }
        return false
    }

    var marked = 0
    do {
        var found = false
        for (func in funMgr.getFunctions(true)) {
            monitor?.checkCancelled()
            if (func.hasNoReturn() || func.isThunk || func.isExternal) continue
            if (listing.getInstructionAt(func.entryPoint) == null || canReturn(func)) continue
            func.setNoReturn(true)
            marked++
            found = true
        }
    } while (found)
    return marked
}
