package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.importer.MessageLog
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
 * the classic `lea r,[r]` forms — `8d 76 00`, `8d bc 27 …`). Rather than chase the byte tables, each
 * undefined run is pseudo-disassembled and its *leading* effect-free instructions (the padding that
 * aligns whatever follows) are collapsed into one Alignment; real data after the padding is left
 * alone (e.g. a keyword string table sitting between the padding and its loader function).
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

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        monitor ?: return false
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
        log?.appendMsg(NAME, "collapsed $marked alignment-padding run(s)")
        return true
    }

    /** Bytes of leading effect-free padding at the start of [range] (0 if it doesn't begin with any). */
    private fun leadingFillerLength(pdis: PseudoDisassembler, range: AddressRange): Long {
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
