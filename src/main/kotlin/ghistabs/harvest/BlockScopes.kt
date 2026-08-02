package ghistabs.harvest

import ghidra.program.model.address.Address
import ghistabs.parse.StabType
import kotlinx.serialization.Serializable

/**
 * One lexical block of a function: its address range, the locals it owns, and its nested blocks.
 *
 * Ownership is *the run of symbol records since the previous bracket*, not containment between a
 * bracket pair. gcc's `dbxout_block` (dbxout.c) says so outright — "In dbx format, the syms of a
 * block come before the N_LBRAC. If nothing is output, we don't need the N_LBRAC, either" — and
 * every fixture agrees: the next bracket record after a run of locals is an N_LBRAC 12863/12863
 * times, never an N_RBRAC.
 */
@Serializable
data class BlockScope(
    @Serializable(with = AddressSerializer::class)
    val start: Address,
    @Serializable(with = AddressSerializer::class)
    val end: Address,
    val locals: List<SymbolRecord>,
    val children: List<BlockScope> = emptyList(),
)

/** Bracket records (absolute address, stream index) → the function's block tree. */
internal fun buildBlocks(brackets: List<Bracket>, locals: List<SymbolRecord>): List<BlockScope> {
    class Frame(
        val start: Address,
        val locals: List<SymbolRecord>,
        val children: MutableList<BlockScope> = mutableListOf(),
    )

    val ordered = locals.sortedBy { it.recordIndex }
    var next = 0
    fun claimBefore(recordIndex: Int) = buildList {
        while (next < ordered.size && ordered[next].recordIndex < recordIndex) add(ordered[next++])
    }

    val stack = mutableListOf<Frame>()
    val roots = mutableListOf<BlockScope>()
    for ((type, addr, recordIndex) in brackets) {
        val claimed = claimBefore(recordIndex)
        when (type) {
            // A run of syms with no N_LBRAC of its own can only belong to the block being closed.
            StabType.N_RBRAC if stack.isNotEmpty() -> stack.removeAt(stack.size - 1).let { frame ->
                val block = BlockScope(frame.start, addr, frame.locals + claimed, frame.children)
                (stack.lastOrNull()?.children ?: roots).add(block)
            }

            StabType.N_LBRAC -> stack.add(Frame(addr, claimed))

            else -> {}
        }
    }
    return roots
}

/** Line entries this block's own code produced — inside its range, outside every child's. */
private fun BlockScope.ownLines(lines: List<LineEntry>) = lines.filter {
    it.addr in start..<end && children.none { c -> it.addr in c.start..<c.end }
}

/**
 * Source file per local `recordIndex`, resolved top-down: the file whose N_SLINEs in the block's
 * own code carry the local's decl line, else the block's own code if it is all one file, else the
 * enclosing block's answer (the outermost block inherits the function's own source).
 *
 * The block is the only signal there is. A local's N_SOL says nothing: gcc emits the whole block
 * tree from `dbxout_function_decl` *after* the body, so every local in a function carries whatever
 * file the last line note happened to be in.
 */
internal fun List<BlockScope>.attributedSources(lines: List<LineEntry>, functionSource: String): Map<Int, String> {
    val out = mutableMapOf<Int, String>()
    fun walk(blocks: List<BlockScope>, inherited: String) {
        for (block in blocks) {
            val own = block.ownLines(lines)
            val blockSource = own.mapTo(mutableSetOf()) { it.source }.singleOrNull() ?: inherited
            block.locals.forEach { local ->
                out[local.recordIndex] = own.filter { it.line == local.declLine }
                    .mapTo(mutableSetOf()) { it.source }.singleOrNull() ?: blockSource
            }
            walk(block.children, blockSource)
        }
    }
    walk(this, functionSource)
    return out
}

/**
 * Local `recordIndex` → the offset from [entry] at which its block opens. gcc's lexical scope *is*
 * the live range, which is what Ghidra's `firstUseOffset` wants: a register local declared from
 * entry claims the register for the whole function, so N inlined copies of the same name collapse
 * onto one variable and all but the first are dropped.
 */
internal fun List<BlockScope>.firstUseOffsets(entry: Address): Map<Int, Int> = buildMap {
    fun walk(blocks: List<BlockScope>) {
        blocks.forEach { block ->
            val offset = (block.start.offset - entry.offset).toInt()
            block.locals.forEach { put(it.recordIndex, offset) }
            walk(block.children)
        }
    }
    walk(this@firstUseOffsets)
}

/**
 * Resolve the block tree and repoint every function-scope symbol at the source file it was really
 * compiled from. Params belong to the function; locals to their block (see [attributedSources]).
 */
internal fun OpenFunction.resolveBlocks() {
    val functionSource = lineEntries.minByOrNull { it.addr.offset }?.source ?: cu.filename
    val sources = buildBlocks(scopeBrackets, locals).attributedSources(lineEntries, functionSource)
    locals.replaceAll { local -> sources[local.recordIndex]?.let { local.copy(sourceFile = it) } ?: local }
    params.replaceAll { it.copy(sourceFile = functionSource) }
    blocks = buildBlocks(scopeBrackets, locals)
}
