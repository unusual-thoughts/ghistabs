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
        symbolNameAt(addr)?.let { sym ->
            "$sym → $body"
        } ?: body
    }

    else -> null
}

fun Address.render(program: Program) = program.describeAddress(this)
