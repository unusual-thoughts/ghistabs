package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.AlignmentDataType
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.forceCreateData

/**
 * Marks compiler alignment padding in executable memory as [AlignmentDataType], so downstream passes
 * (the stabs importer's data-coverage report) don't mistake it for undescribed data. Runs before
 * [StabsAnalyzer]; re-runnable (idempotent — already-defined padding is skipped).
 *
 * GCC 3.4.4 emits `.p2align`; GAS fills the gap with whatever NOP idiom fits (`0x90`, `0f 1f …`, and
 * the classic `lea r,[r]` forms — `8d 76 00`, `8d bc 27 …`). For a wider gap it uses the jump-over-fill
 * idiom instead (`eb 0d 90…`): an unconditional forward JMP to the aligned boundary, NOPs behind it.
 * Rather than chase the byte tables, each undefined run is pseudo-disassembled and its *leading*
 * effect-free padding (see [leadingFillerLength]) is collapsed into one Alignment; real data after the
 * padding is left alone (e.g. a keyword string table sitting between the padding and its loader function).
 */
class FillerByteAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Collapses compiler NOP alignment padding in code into Alignment data.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.before()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun getDefaultEnablement(program: Program?) = true

    override fun canAnalyze(program: Program?) = program?.memory?.executeSet?.isEmpty == false

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        val listing = program.listing
        val bookmarks = program.bookmarkManager
        val target = program.memory.executeSet.intersect(set ?: program.memory.executeSet)
        val pdis = PseudoDisassembler(program)

        var marked = 0
        for (range in listing.getUndefinedRanges(target, false, monitor)) {
            monitor.checkCancelled()
            for ((at, len) in fillSpans(pdis, range)) {
                if (runCatching { program.forceCreateData(at, AlignmentDataType(), len.toInt()) }.isSuccess) {
                    bookmarks.setBookmark(at, BookmarkType.ANALYSIS, NAME, "collapsed $len filler bytes")
                    marked++
                }
            }
        }
        if (marked != 0) {
            log.appendMsg(NAME, "collapsed $marked alignment-padding run(s)")
        }
        return true
    }

    /**
     * Every `(address, length)` span of effect-free padding in [range], in address order.
     *
     * Two GAS `.p2align` forms are recognised:
     *  - a plain run of NOP-equivalent instructions, which only ever leads the range (anything
     *    before it would have kept the bytes out of the undefined set);
     *  - the jump-over-fill idiom (`eb 0d 90…`): an unconditional forward JMP whose target is the
     *    aligned boundary, every skipped byte NOP-equivalent. That one is found *anywhere* in the
     *    range, not just at its head — gcc parks dead tails behind a `ret` (`add [esp+4],-4` on
     *    cryptopp), so the padding gcc wrote for the next function starts mid-range.
     *
     * The jump target is just the boundary — the next function, or a constant block gcc parked in
     * `.text` — so the whole `[jmp, target)` span collapses regardless of what follows it.
     *
     * Every offset is tried for the JMP, not the instruction starts a linear walk would produce:
     * the bytes ahead of the padding are dead, so "instruction start" is not defined for them, and
     * a dead tail that happens to decode across the `eb` hides the padding behind it (one site per
     * binary on some, none on cryptopp — where the junk decodes
     * to exactly the right length by luck).
     */
    private fun fillSpans(pdis: PseudoDisassembler, range: AddressRange): List<Pair<Address, Long>> = buildList {
        var addr = range.minAddress
        nopRunLength(pdis, addr, range.maxAddress).takeIf { it > 0 }?.let {
            add(addr to it)
            addr = addr.add(it)
        }
        while (addr <= range.maxAddress) {
            val fill = runCatching { pdis.disassemble(addr) }.getOrNull()
                ?.let { jumpOverFillLength(pdis, it, range.maxAddress) }
            if (fill != null) add(addr to fill)
            addr = addr.add(fill ?: 1L)
        }
    }

    /** Length of the jump-over-fill idiom led by [jmp], or null if [jmp] doesn't lead one. */
    private fun jumpOverFillLength(pdis: PseudoDisassembler, jmp: Instruction, last: Address): Long? {
        if (!jmp.flowType.isJump || jmp.flowType.isConditional) return null
        val target = jmp.flows.singleOrNull()?.takeIf { it > jmp.address } ?: return null
        return target.subtract(jmp.address).takeIf {
            it <= last.subtract(jmp.address) + 1 &&
                nopRunFillsGap(pdis, jmp.address.add(jmp.length.toLong()), target)
        }
    }

    /** Bytes of NOP-equivalent instructions starting at [from], not running past [last]. */
    private fun nopRunLength(pdis: PseudoDisassembler, from: Address, last: Address): Long {
        var addr = from
        while (addr <= last) {
            val insn = runCatching { pdis.disassemble(addr) }.getOrNull() ?: break
            if (insn.length == 0 || !insn.isNopEquivalent() || addr.add(insn.length - 1L) > last) break
            addr = addr.add(insn.length.toLong())
        }
        return addr.subtract(from)
    }

    /** True when every instruction in `[from, to)` is NOP-equivalent and the run lands exactly on [to]. */
    private fun nopRunFillsGap(pdis: PseudoDisassembler, from: Address, to: Address): Boolean {
        var addr = from
        while (addr < to) {
            val insn = runCatching { pdis.disassemble(addr) }.getOrNull() ?: return false
            if (insn.length == 0 || !insn.isNopEquivalent()) return false
            addr = addr.add(insn.length.toLong())
        }
        return addr == to
    }

    /**
     * NOP, or a self-referential `lea r,[r(+0)]` / `mov r,r` / `xchg r,r` — GAS's alignment fillers
     * (`8d 76 00`, `89 f6`, `87 …`), all state-preserving.
     */
    private fun Instruction.isNopEquivalent() = when (mnemonicString) {
        "NOP" -> true
        "LEA", "MOV", "XCHG" -> resultObjects.singleOrNull()?.let { it == inputObjects.singleOrNull() } == true
        else -> false
    }

    companion object {
        const val NAME = "Filler Byte Condenser"
    }
}
