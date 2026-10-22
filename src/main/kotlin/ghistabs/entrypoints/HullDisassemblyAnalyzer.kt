package ghistabs.entrypoints

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.PseudoFlowProcessor
import ghidra.app.util.PseudoInstruction
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.Instructions
import ghistabs.MAX_FILL
import ghistabs.fillJumpLength
import ghistabs.instructions
import ghistabs.isNopEquivalent
import ghistabs.tiles

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
            val hull = AddressSet(fn.entryPoint, fn.body.maxAddress).intersect(executable)
            for (range in program.listing.getUndefinedRanges(hull, false, monitor)) {
                if (code.tiles(range)) code.codeRuns(range).forEach { recover[it] = "inside $fn 's hull" }
            }
            for (tail in program.deadTails(fn, pseudo)) {
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
private fun Instructions.codeRuns(range: AddressRange): List<AddressRange> = buildList {
    val limit = range.maxAddress.next() ?: return@buildList
    var start: Address? = null
    var addr = range.minAddress
    while (addr < limit) {
        val insn = at(addr) ?: break
        // The idiom may run past the gap: a stray reference can disassemble a NOP of its fill.
        val fill = if (insn.isNopEquivalent()) insn.length.toLong() else fillJumpLength(insn, addr.add(MAX_FILL))
        if (fill != null) {
            start?.let { add(AddressRangeImpl(it, addr.previous())) }
            start = null
        } else if (start == null) {
            start = addr
        }
        addr = addr.add(fill ?: insn.length.toLong())
    }
    start?.let { add(AddressRangeImpl(it, addr.previous())) }
}

/**
 * The undefined code right after [fn]'s calls to non-returning functions, past its last instruction:
 * Ghidra's own pseudo flow walk from there, following only flows through undefined bytes. Every way
 * out must be a return or a jump to an instruction of [fn] (the join), and one must exist; anything
 * else it reaches — a bad decode, the middle of an instruction, another function — rejects the tail.
 */
private fun Program.deadTails(fn: Function, pseudo: PseudoDisassembler): List<AddressSetView> {
    val end = fn.body.maxAddress
    return (listing.getInstructions(fn.body, true) as Iterable<Instruction>).asSequence()
        .filter { it.flowType.isCall && it.callsNoReturn(this) }
        .mapNotNull { call -> call.maxAddress.next()?.takeIf { it > end && listing.isUndefined(it, it) } }
        .mapNotNull { start ->
            val walk = DeadTailWalk(this, fn)
            val reached = pseudo.followSubFlows(start, MAX_TAIL, walk)
            reached.subtract(walk.joins).takeIf { walk.ok && walk.exits && it.minAddress == start }
        }.toList()
}

private fun Instruction.callsNoReturn(program: Program) =
    flows.singleOrNull()?.let { program.functionManager.getFunctionAt(it) }?.hasNoReturn() == true

/** A tail is a few blocks of cleanup; a walk that long has run off into something else. */
private const val MAX_TAIL = 64

private class DeadTailWalk(private val program: Program, private val fn: Function) : PseudoFlowProcessor {
    val joins = AddressSet()
    var ok = true
    var exits = false
    private var seen = 0

    override fun process(instr: PseudoInstruction?): Boolean {
        if (instr == null || ++seen >= MAX_TAIL) return false.also { ok = false }
        if (program.listing.isUndefined(instr.minAddress, instr.maxAddress)) return true
        // Already code: fine only where it is an instruction of fn, the join the tail goes back to.
        val join = program.listing.getInstructionAt(instr.minAddress)?.takeIf { it.address in fn.body }
        if (join == null) ok = false else joins.add(instr.minAddress, instr.maxAddress).also { exits = true }
        return ok
    }

    override fun followFlows(instr: PseudoInstruction): Boolean {
        if (instr.minAddress in joins) return false
        val flow = instr.flowType
        if ((flow.isTerminal && !flow.isCall) || (flow.isCall && instr.callsNoReturn(program))) {
            exits = true
            return false
        }
        return true
    }
}
