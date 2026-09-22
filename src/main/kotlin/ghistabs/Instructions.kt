package ghistabs

import ghidra.app.util.PseudoDisassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.listing.Instruction

/**
 * Reading a stretch of memory as instructions, and recognising GAS alignment fill in it.
 *
 * `FillerByteAnalyzer` collapses fill into one Alignment; `HullDisassemblyAnalyzer` asks whether a
 * gap is nothing but fill before disassembling it. Both read the *bytes* rather than the listing —
 * fill is fill whether or not something decoded it — so [Instructions] exists to keep that choice in
 * one place, and every walk below is written once against it.
 */
fun interface Instructions {
    /** The instruction at [address], or null where nothing decodes (or nothing is there). */
    fun at(address: Address): Instruction?
}

/** Instructions decoded from the bytes, whatever the listing has made of them. */
val PseudoDisassembler.instructions get() = Instructions { addr ->
    runCatching { disassemble(addr) }.getOrNull()?.takeIf { it.length > 0 }
}

/**
 * NOP, or a self-referential `lea r,[r(+0)]` / `mov r,r` / `xchg r,r` — GAS's alignment fillers
 * (`8d 76 00`, `89 f6`, `87 …`), all state-preserving.
 */
fun Instruction.isNopEquivalent() = when (mnemonicString) {
    "NOP" -> true
    "LEA", "MOV", "XCHG" -> resultObjects.singleOrNull()?.let { it == inputObjects.singleOrNull() } == true
    else -> false
}

/** Where the NOP-equivalent run starting at [from] ends, never past [limit]; [from] if none starts there. */
fun Instructions.nopRunEnd(from: Address, limit: Address): Address {
    var addr = from
    while (addr < limit) {
        val insn = at(addr)?.takeIf { it.isNopEquivalent() } ?: break
        val next = runCatching { addr.add(insn.length.toLong()) }.getOrNull() ?: break
        if (next > limit) break
        addr = next
    }
    return addr
}

/**
 * Length of the jump-over-fill idiom [jmp] leads — `eb 0d 90…`, an unconditional forward jump to the
 * aligned boundary with NOPs behind it — or null where [jmp] leads no such thing.
 *
 * The whole idiom must fit below [limit] (exclusive) and the NOPs must land exactly on the jump's
 * target: fill that stops short of where the jump goes is not fill, it is a jump over something.
 */
fun Instructions.fillJumpLength(jmp: Instruction, limit: Address): Long? {
    if (!jmp.flowType.isJump || jmp.flowType.isConditional) return null
    val target = jmp.flows.singleOrNull()?.takeIf { it > jmp.address && it <= limit } ?: return null
    val afterJmp = jmp.address.add(jmp.length.toLong())
    return target.subtract(jmp.address).takeIf { nopRunEnd(afterJmp, target) == target }
}

/** A jump-over-fill skips to the next alignment boundary, so 16 bytes bounds the whole idiom. */
const val MAX_FILL = 16L

/**
 * Whether [range] tiles exactly — every byte decoding to an instruction [accept] takes, the last one
 * ending on the range's final byte. The default accepts anything, which is "this is all code".
 */
fun Instructions.tiles(range: AddressRange, accept: (Instruction) -> Boolean = { true }): Boolean {
    val limit = range.maxAddress.next() ?: return false
    var addr = range.minAddress
    while (addr < limit) {
        val insn = at(addr)?.takeIf(accept) ?: return false
        addr = runCatching { addr.add(insn.length.toLong()) }.getOrNull() ?: return false
        if (addr > limit) return false
    }
    return true
}

/** Nothing in [range] but fill: NOP-equivalents, and the jump-over-fill idiom's own forward jump. */
fun Instructions.isAllPadding(range: AddressRange) = range.maxAddress.next()?.let { limit ->
    tiles(range) { it.isNopEquivalent() || fillJumpLength(it, limit) != null }
} == true
