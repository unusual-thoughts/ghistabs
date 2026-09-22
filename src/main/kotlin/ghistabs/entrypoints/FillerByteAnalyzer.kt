package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.AlignmentDataType
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.*

/**
 * Marks compiler alignment padding in executable memory as [AlignmentDataType], so downstream passes
 * (the stabs importer's data-coverage report) don't mistake it for undescribed data. Runs before
 * [StabsAnalyzer]; re-runnable (idempotent — already-defined padding is skipped).
 *
 * GCC 3.4.4 emits `.p2align`; GAS fills the gap with whatever NOP idiom fits (`0x90`, `0f 1f …`, and
 * the classic `lea r,[r]` forms — `8d 76 00`, `8d bc 27 …`). For a wider gap it uses the jump-over-fill
 * idiom instead (`eb 0d 90…`): an unconditional forward JMP to the aligned boundary, NOPs behind it.
 * Rather than chase the byte tables, each undefined run is pseudo-disassembled and its *leading*
 * effect-free padding is collapsed into one Alignment; real data after the
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
        val code = PseudoDisassembler(program).instructions

        var marked = 0
        for (range in listing.getUndefinedRanges(target, false, monitor)) {
            monitor.checkCancelled()
            for ((at, len) in program.fillSpans(code, range)) {
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
     * That span may finish *past* the undefined range: a stray reference into fill gets a byte of it
     * disassembled, which ends the range early without making the byte anything but fill (a `.data`
     * word equal to `0000ffff` costs `0000fff0` its Alignment on `iostream_test_aout_gcc263_fullstabs`
     * — Ghidra's Data Reference analyzer resolves it against `.text` and disassembles one NOP). The
     * bound is therefore the idiom's own [MAX_FILL], read off the bytes rather than the listing, and
     * [forceCreateData] clears whatever was decoded there. What it may not cross is a function: fill
     * inside a live body is that body's `-falign-loops` padding, and collapsing it would punch a hole
     * through the instruction stream.
     *
     * Every offset is tried for the JMP, not the instruction starts a linear walk would produce:
     * the bytes ahead of the padding are dead, so "instruction start" is not defined for them, and
     * a dead tail that happens to decode across the `eb` hides the padding behind it (one site per
     * binary on some, none on cryptopp — where the junk decodes
     * to exactly the right length by luck).
     */
    private fun Program.fillSpans(code: Instructions, range: AddressRange): List<Pair<Address, Long>> = buildList {
        val limit = range.maxAddress.next() ?: return@buildList
        var addr = range.minAddress
        code.nopRunEnd(addr, limit).takeIf { it > addr }?.let {
            add(addr to it.subtract(addr))
            addr = it
        }
        while (addr < limit) {
            val fill = code.at(addr)
                ?.let { code.fillJumpLength(it, addr.add(MAX_FILL)) }
                ?.takeIf { noFunctionIn(addr, it) }
            if (fill != null) add(addr to fill)
            addr = addr.add(fill ?: 1L)
        }
    }

    /** No function claims any of `[at, at + len)` — fill inside a live body is that body's own. */
    private fun Program.noFunctionIn(at: Address, len: Long) =
        !functionManager.getFunctionsOverlapping(AddressSet(at, at.add(len - 1))).hasNext()

    companion object {
        const val NAME = "Filler Byte Condenser"
    }
}
