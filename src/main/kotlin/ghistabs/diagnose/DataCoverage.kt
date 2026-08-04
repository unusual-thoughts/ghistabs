package ghistabs.diagnose

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.Program
import ghistabs.importer.ImportContext
import ghistabs.inHull
import ghistabs.parse.StabReader
import ghistabs.parse.StabType

// a.out keeps its stabs in the linker symbol table, so `.symtab`/`.strtab` are debug info here too.
private val NON_DATA_BLOCKS = setOf(".stab", ".stabstr", ".symtab", ".strtab", ".comment")

// Each CU's .bss segment is 16-byte aligned (variables pack within it), so the undefined gap at a
// CU boundary is ≤15 bytes of alignment padding — a run this long or longer is undescribed data.
private const val ALIGN_PADDING = 16L

/**
 * Report data bytes that no code unit describes — undefined ranges Ghidra never turned into data.
 * Runs last, after globals/statics/vtables/RTTI/demangled labels are applied (and after the filler
 * analyzer has collapsed alignment padding), so both defined data and padding count as covered.
 *
 * Non-code segments (.data/.rdata/.bss/…) are swept directly; initialized zero-fill runs are ignored
 * and .bss keeps only runs ≥ one alignment window (the ≤15-byte CU-boundary padding is dropped).
 * Read-only data serialized into .text (a CU whose linker had no separate .rodata) is reported too:
 * an undefined .text run inside a function body is a missed-code hole (`text-undisassembled-code`),
 * one outside every function is that CU's undescribed rodata (`text-data-no-coverage`, attributed to
 * the enclosing N_SO source file).
 */
fun ImportContext<*>.analyzeDataCoverage() {
    monitor.message = "Stabs: analysing data coverage"
    val cuStarts by lazy { cuTextStarts() }
    for (block in program.memory.blocks) {
        if (!block.isRead || block.isMapped || block.name in NON_DATA_BLOCKS || block.name.startsWith(".debug")) {
            continue
        }
        val undefined = program.listing.getUndefinedRanges(AddressSet(block.start, block.end), false, monitor)
        if (block.isExecute) {
            undefined.forEach {
                reportTextRun(it, cuStarts)
            }
        } else {
            undefined.forEach { reportDataRun(block, it) }
        }
    }
}

private fun ImportContext<*>.reportDataRun(block: ghidra.program.model.mem.MemoryBlock, range: AddressRange) {
    val reportable = if (block.isInitialized) !range.isAllZero(program) else range.length >= ALIGN_PADDING
    if (reportable) {
        debug(
            "data-no-coverage",
            "@ ${range.minAddress}..${range.maxAddress} (${range.length} bytes) in ${block.name}",
            address = range.minAddress,
        )
    }
}

private fun ImportContext<*>.reportTextRun(range: AddressRange, cuStarts: List<Pair<Address, String>>) {
    if (range.length < program.defaultPointerSize) return
    // Inside a function's convex hull [entry, maxBody] → a hot/cold split hole or EH fragment Ghidra
    // left undisassembled, not data. getFunctionContaining sees only the body, so it misses holes.
    if (program.functionManager.inHull(range.minAddress)) {
        debug("text-undisassembled-code", "@ ${range.minAddress} (${range.length} bytes)", address = range.minAddress)
        return
    }
    val cu = cuStarts.lastOrNull { it.first <= range.minAddress }?.let { " in ${it.second}" }.orEmpty()
    debug(
        "text-data-no-coverage",
        "@ ${range.minAddress}..${range.maxAddress} (${range.length} bytes)$cu",
        address = range.minAddress,
    )
}

/** N_SO source-file text starts, sorted — each bounds the CU whose code (and rodata) begins there. */
private fun ImportContext<*>.cuTextStarts(): List<Pair<Address, String>> =
    StabReader.fromProgram(program)?.physicalRecords()
        ?.filter { it.type == StabType.N_SO && it.name.isNotEmpty() && !it.name.endsWith('/') && it.value != 0L }
        ?.map { resolver.buildAddress(it.value) to it.name }
        ?.sortedBy { it.first }
        ?.toList()
        .orEmpty()

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
