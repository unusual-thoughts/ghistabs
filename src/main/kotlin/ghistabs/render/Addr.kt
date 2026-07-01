package ghistabs.render

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType

private fun Program.symbolNameAt(addr: Address) = symbolTable.getPrimarySymbol(addr)
    ?.takeIf { it.source != SourceType.DEFAULT }
    ?.getName(true)

/**
 * Ghidra-listing description for [addr]: the primary symbol if any
 * (so a function entry shows as `foo:` and a data label as
 * `gGlobal:`), plus the code unit's printable form (instruction
 * mnemonic + operands, or the data type / value). Returns null if
 * nothing meaningful is at this address.
 */
private fun Program.describeAddress(addr: Address): String? = when (val cu = listing.getCodeUnitAt(addr)) {
    is Instruction -> functionManager.getFunctionContaining(addr)?.getName(true)
        ?: symbolNameAt(addr)

    is Data -> {
        val body = listOfNotNull(
            cu.dataType.name,
            runCatching { cu.value?.toString() }.getOrNull(),
        ).joinToString(" = ")
        symbolNameAt(addr)?.let { sym -> "$sym → $body" } ?: body
    }

    else -> null
}

fun Address.render(program: Program) = program.describeAddress(this)

/**
 * Collapse [addrs] into `0xS-0xE` runs where consecutive entries cover back-to-back code
 * units (instruction.length apart), comma-joined — so the prologue's 5 N_SLINEs at
 * `0x401000..0x40100f` read as `0x401000-0x40100f`, not a comma list.
 */
fun formatAddrRuns(addrs: List<Address>, program: Program): String {
    if (addrs.isEmpty()) return ""
    val sorted = addrs.sortedBy { it.offset }
    val runs = mutableListOf<Pair<Address, Address>>()
    var runStart = sorted[0]
    var runEnd = sorted[0]
    for (cur in sorted.drop(1)) {
        val inst = program.listing.getInstructionAt(runEnd)
        val expectedNext = inst?.next?.address
            ?: program.listing.getCodeUnitAt(runEnd)?.takeIf { it.length > 0 }?.let { runEnd.add(it.length.toLong()) }
        if (cur == expectedNext) {
            runEnd = cur
        } else {
            runs += runStart to runEnd
            runStart = cur
            runEnd = cur
        }
    }
    runs += runStart to runEnd
    fun hex(a: Address) = "0x" + a.offset.toString(16).padStart(8, '0')
    return runs.joinToString(", ") { (s, e) -> if (s == e) hex(s) else "${hex(s)}-${hex(e)}" }
}
