package ghistabs

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

/**
 * Recovers code Ghidra left undisassembled *inside* a function's extent — hot/cold split holes and
 * exception landing pads reachable only by unwinding, not normal flow. For each undefined run within
 * some function's convex hull `[entry, body.maxAddress]` that pseudo-disassembles cleanly (every byte
 * decodes to a valid instruction), it runs [DisassembleCommand] for real. The convex hull is the
 * discriminator: undefined *outside* every function is data, so it's left alone.
 *
 * Runs after Ghidra's function analysis (hulls exist) and before [StabsAnalyzer] / its data-coverage
 * report, which would otherwise flag these fragments as undescribed data. Re-runnable.
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
        val fm = program.functionManager
        val listing = program.listing
        val pdis = PseudoDisassembler(program)
        val target = program.memory.executeSet.intersect(set ?: program.memory.executeSet)

        val recover = AddressSet()
        for (range in listing.getUndefinedRanges(target, false, monitor)) {
            monitor.checkCancelled()
            if (fm.inHull(range.minAddress) && pdis.tilesCleanly(range)) {
                recover.add(range.minAddress, range.maxAddress)
            }
        }
        if (!recover.isEmpty) {
            DisassembleCommand(recover, null, true).applyTo(program, monitor)
            for (range in recover) {
                val fn = fm.getFunctionWrapping(range.minAddress)
                program.bookmarkManager.setBookmark(
                    range.minAddress,
                    BookmarkType.ANALYSIS,
                    NAME,
                    "Disassembled because inside $fn 's hull",
                )
            }
            log?.appendMsg(NAME, "recovered ${recover.numAddresses} in-function code bytes")
        }
        return true
    }

    /** Every byte of [range] decodes to a valid instruction, tiling exactly to the end. */
    private fun PseudoDisassembler.tilesCleanly(range: AddressRange): Boolean {
        var addr = range.minAddress
        while (addr <= range.maxAddress) {
            val insn = runCatching { disassemble(addr) }.getOrNull() ?: return false
            if (insn.length == 0) return false
            addr = runCatching { addr.add(insn.length.toLong()) }.getOrNull() ?: return false
        }
        return true
    }

    companion object {
        const val NAME = "In-Function Gap Disassembler"
    }
}
