package ghistabs.entrypoints

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.PseudoFlowProcessor
import ghidra.app.util.PseudoInstruction
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.*

/**
 * Recovers code Ghidra left undisassembled *inside* a function's extent — hot/cold split holes and
 * exception landing pads reachable only by unwinding, not normal flow. For each undefined run within
 * some function's convex hull `[entry, body.maxAddress]` that pseudo-disassembles cleanly (every byte
 * decodes to a valid instruction), it runs [DisassembleCommand] for real. The convex hull is the
 * discriminator: undefined *outside* every function is data, so it's left alone.
 *
 * Ghidra hands a function analyzer the entry points of the functions added or changed, not their
 * bodies, and a gap is in no body: the hull of each of those functions is what gets searched.
 *
 * The hull runs on over an SJLJ function's landing pads when they lie past its body's last instruction.
 * [SjljLsdaAnalyzer] adds them to the body, but Ghidra recomputes a body from its entry once a call in
 * it turns out not to return, and drops them, leaving the bytes after a pad's own non-returning call
 * (`call __throw_ios_failure; add $0x10,%esp` in libstdc++'s `ios_base::_M_grow_words`) in no hull.
 * That recompute changes the body, so this runs again for the function and finds them through the
 * receiver's address the body still stores.
 *
 * One more run past the hull: the return path a caller's compiler wrote after a call it did not know
 * cannot return, `call __throw_out_of_range; add $0x10,%esp; jmp <join>`. Once the callee is marked
 * non-returning nothing reaches it, and gcc puts that out-of-line block last, so it trails the body's
 * last instruction. Ghidra's pseudo flow walk ([PseudoDisassembler.followSubFlows]) takes it from the
 * call to every jump back into the function and every return, and it is kept only if it gets there.
 *
 * Runs after Ghidra's function analysis (hulls exist) and before [StabsAnalyzer] / its data-coverage
 * report, which would otherwise flag these fragments as undescribed data. Re-runnable.
 *
 * The alignment fill in a gap is left to [FillerByteAnalyzer], which runs later and
 * collapses it to one Alignment. gcc 2.x aligns the jump target inside a function — the epilogue a
 * body's `JMP` skips to — so its fill lands in the hull, unreachable but surrounded by code, and
 * disassembling it buried the Alignment under a couple of dozen orphan NOPs (89 of 249 sites on
 * `iostream_test_aout_gcc263_fullstabs`). gcc 3.x pads between functions, outside every hull, which
 * is why this never showed up on the mingw corpus. A gap can hold both: gcc 2.x's dead `xor %eax,%eax;
 * jmp` between two runs of fill, so only the runs between the fill are disassembled.
 */
class HullDisassemblyAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Disassembles undefined code inside function bodies (hot/cold holes, EH landing pads).",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.FUNCTION_ANALYSIS.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun getDefaultEnablement(program: Program?) = true

    override fun canAnalyze(program: Program?) = program?.memory?.executeSet?.isEmpty == false

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        monitor ?: return false
        val pseudo = PseudoDisassembler(program)
        val code = pseudo.instructions
        val executable = program.memory.executeSet

        val recover = mutableMapOf<AddressRange, String>()
        for (fn in program.functionManager.getFunctions(set ?: executable, true)) {
            monitor.checkCancelled()
            if (fn.isExternal || fn.isThunk) continue
            val body = program.unwoundBody(fn, monitor)
            val hull = AddressSet(fn.entryPoint, body.maxAddress).intersect(executable)
            for (range in program.listing.getUndefinedRanges(hull, false, monitor)) {
                if (code.tiles(range)) code.codeRuns(range).forEach { recover[it] = "inside $fn 's hull" }
            }
            for (tail in program.deadTails(body, pseudo)) {
                for (range in tail) recover[range] = "dead return path after a call in $fn"
            }
        }
        if (recover.isNotEmpty()) {
            val all = AddressSet().apply { recover.keys.forEach(::add) }
            DisassembleCommand(all, null, true).applyTo(program, monitor)
            for ((range, why) in recover) {
                program.bookmarkManager.setBookmark(range.minAddress, BookmarkType.ANALYSIS, NAME, "Disassembled: $why")
            }
            log?.appendMsg(NAME, "recovered ${all.numAddresses} in-function code bytes")
        }
        return true
    }

    companion object {
        const val NAME = "In-Function Gap Disassembler"
    }
}

/**
 * [range] without its alignment fill — NOP-equivalents and jump-over-fill idioms — as the runs of
 * code left between them. [range] must already tile.
 */
private fun Instructions.codeRuns(range: AddressRange): AddressSetView = AddressSet().apply {
    val limit = range.maxAddress.next() ?: return@apply
    var start: Address? = null
    var cur = range.minAddress
    fun nextRun() = start?.let {
        add(it..<cur)
        start = null
    }
    while (cur < limit) {
        val insn = at(cur) ?: break
        // The idiom may run past the gap: a stray reference can disassemble a NOP of its fill.
        val fill = nopRunLength(cur, limit) ?: fillJumpLength(insn, cur.add(MAX_FILL))
        if (fill == null) start = start ?: cur else nextRun()
        cur += fill ?: insn.length.toLong()
    }
    nextRun()
}

/**
 * [fn]'s body and the SJLJ receiver past it whose address the body stores (`movl $resume, jbuf[1]`),
 * as [SjljLsdaAnalyzer] labelled it, with the flow from there: the landing pads it dispatches to,
 * which only the unwinder reaches. Ghidra recomputes a body from its entry whenever a call in it
 * turns out not to return, which drops them again however [SjljLsdaAnalyzer] laid them.
 */
private fun Program.unwoundBody(fn: Function, monitor: TaskMonitor): AddressSetView {
    val end = fn.body.maxAddress
    return listing.getInstructions(fn.body, true).iterator().asSequence()
        .flatMap { it.referencesFrom.asSequence() }
        .map { it.toAddress }
        .filter { it > end && functionManager.getFunctionContaining(it) == null }
        .filter { at -> symbolTable.getSymbols(at).any { it.name == "${SjljLsdaAnalyzer.RESUME_LABEL}_$at" } }
        .fold(fn.body) { body, at -> body.union(CreateFunctionCmd.getFunctionBody(this, at, monitor)) }
}

/**
 * The undefined code right after the calls to non-returning functions in a function's [body] (with
 * its pads, from [unwoundBody]), past its last instruction: Ghidra's own pseudo flow walk from there,
 * following flows only through undefined bytes and stopping at another non-returning call. Code already
 * there must be an instruction of [body], the join the tail goes back to; anything else it reaches — a
 * bad decode, the middle of an instruction, another function — rejects the tail.
 */
private fun Program.deadTails(body: AddressSetView, pseudo: PseudoDisassembler): List<AddressSetView> {
    val end = body.maxAddress
    fun Instruction.callsNoReturn() = flows.singleOrNull()
        ?.let { functionManager.getFunctionAt(it) }?.hasNoReturn() == true
    fun PseudoInstruction.isUndefined() = listing.isUndefined(minAddress, maxAddress)
    fun PseudoInstruction.backInFn() = minAddress in body && listing.getInstructionAt(minAddress) != null

    return listing.getInstructions(body, true).iterator().asSequence()
        .filter { it.flowType.isCall && it.callsNoReturn() }
        .mapNotNull { call -> call.maxAddress.next()?.takeIf { it > end && listing.isUndefined(it, it) } }
        .mapNotNull { start ->
            val walk = object : PseudoFlowProcessor {
                var ok = true
                private var seen = 0

                // Ghidra hands null for a bad decode (followSubFlows' UnknownInstructionException).
                override fun process(instr: PseudoInstruction?) = (
                    instr != null && ++seen < MAX_TAIL && (instr.isUndefined() || instr.backInFn())
                    ).also { ok = it }

                override fun followFlows(instr: PseudoInstruction) = instr.isUndefined() && !instr.callsNoReturn()
            }
            pseudo.followSubFlows(start, MAX_TAIL, walk).subtract(body).takeIf { walk.ok && start in it }
        }.toList()
}

/** Only a bound on a walk gone wrong: an SJLJ landing pad behind a noreturn call runs past 64 instructions. */
private const val MAX_TAIL = 512
