package ghistabs.diagnose

import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Program
import ghistabs.importer.ImportContext

private val NON_DATA_BLOCKS = setOf(".stab", ".stabstr", ".comment")

// Each CU's .bss segment is 16-byte aligned (variables pack within it), so the undefined gap at a
// CU boundary is ≤15 bytes of alignment padding — a run this long or longer is undescribed data.
private const val ALIGN_PADDING = 16L

/**
 * Report data-segment bytes that no code unit describes — undefined ranges Ghidra never turned into
 * data. Runs last, after globals/statics/vtables/RTTI/demangled labels are applied, so their defined
 * data counts as covered. Every non-code segment is swept (.data/.rdata/.bss/…).
 *
 * Padding is skipped: in initialised segments zero-fill runs (alignment / reserved fill) are ignored
 * and only real undescribed bytes surface; uninitialised .bss (unreadable → conceptually all zero)
 * keeps only runs of at least one alignment window, dropping the ≤15-byte CU-boundary padding.
 */
fun ImportContext<*>.analyzeDataCoverage() {
    monitor.message = "Stabs: analysing data coverage"
    val dataBlocks = program.memory.blocks.filter {
        it.isRead &&
            !it.isExecute &&
            !it.isMapped &&
            it.name !in NON_DATA_BLOCKS &&
            !it.name.startsWith(".debug")
    }
    for (block in dataBlocks) {
        val undefined = program.listing.getUndefinedRanges(AddressSet(block.start, block.end), false, monitor)
        for (range in undefined) {
            val reportable = if (block.isInitialized) !range.isAllZero(program) else range.length >= ALIGN_PADDING
            if (reportable) {
                debug(
                    "data-no-coverage",
                    "@ ${range.minAddress}..${range.maxAddress} (${range.length} bytes) in ${block.name}",
                    address = range.minAddress,
                )
            }
        }
    }
}

/** True if every byte of [range] is zero (or unreadable — treat as zero-fill padding). */
private fun AddressRange.isAllZero(program: Program): Boolean {
    val buf = ByteArray(minOf(length, 8192L).toInt())
    var addr = minAddress
    var remaining = length
    while (remaining > 0) {
        val n = minOf(remaining, buf.size.toLong()).toInt()
        val read = runCatching { program.memory.getBytes(addr, buf, 0, n) }.getOrElse { return true }
        if ((0 until read).any { buf[it].toInt() != 0 }) return false
        remaining -= read
        if (read < n) break
        addr = addr.add(read.toLong())
    }
    return true
}
