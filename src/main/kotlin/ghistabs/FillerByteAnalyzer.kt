package ghistabs

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
            val len = leadingFillerLength(pdis, range)
            if (len > 0 &&
                runCatching { listing.createData(range.minAddress, AlignmentDataType(), len.toInt()) }
                    .isSuccess
            ) {
                bookmarks.setBookmark(range.minAddress, BookmarkType.ANALYSIS, NAME, "collapsed $len filler bytes")
                marked++
            }
        }
        if (marked != 0) {
            log.appendMsg(NAME, "collapsed $marked alignment-padding run(s)")
        }
        return true
    }

    /**
     * Bytes of leading effect-free padding at the start of [range] (0 if it doesn't begin with any).
     *
     * Two GAS `.p2align` forms are recognised:
     *  - a plain run of NOP-equivalent instructions;
     *  - the jump-over-fill idiom (`eb 0d 90…`): a leading unconditional forward JMP whose target is
     *    the aligned boundary, every skipped byte NOP-equivalent. The target is just the boundary — the
     *    next function, or (for a string block gcc parked in `.text`) the next constant — so the whole
     *    `[min, target)` span is collapsed regardless of what actually follows it.
     */
    private fun leadingFillerLength(pdis: PseudoDisassembler, range: AddressRange): Long {
        val first = runCatching { pdis.disassemble(range.minAddress) }.getOrNull()
        if (first != null && first.flowType.isJump && !first.flowType.isConditional) {
            val target = first.flows.singleOrNull()
            if (target != null && target > range.minAddress) {
                val fill = target.subtract(range.minAddress)
                if (fill <= range.length &&
                    nopRunFillsGap(pdis, range.minAddress.add(first.length.toLong()), target)
                ) {
                    return fill
                }
            }
        }
        var addr = range.minAddress
        var len = 0L
        while (addr <= range.maxAddress) {
            val insn = runCatching { pdis.disassemble(addr) }.getOrNull() ?: break
            if (insn.length == 0 || !insn.isNopEquivalent() || len + insn.length > range.length) break
            len += insn.length
            addr = addr.add(insn.length.toLong())
        }
        return len
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
