package ghistabs.harvest

import ghidra.program.model.address.Address
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
    val locals: List<Symbol>,
    val children: List<BlockScope> = emptyList(),
    // Resolved by BlockTreeBuilder.finish; null until then. See [finish] for how it is derived.
    @Serializable(with = SourceFileSerializer::class) val source: GhidraSourceFile? = null,
) {
    /** Innermost block covering [addr], or null when [addr] lies outside this one. */
    fun blockAt(addr: Address): BlockScope? =
        if (addr in start..<end) children.firstNotNullOfOrNull { it.blockAt(addr) } ?: this else null
}

/**
 * Assembles a function's block tree from the record stream as it arrives: locals accumulate until a
 * bracket claims them, N_LBRAC opens a scope, N_RBRAC closes one into its parent.
 *
 * Nothing is attributed here — a block's source file comes from the N_SLINEs covering its address
 * range, and those aren't all known until the function ends (nearly always they precede the first
 * bracket, but one function in 23283 across the corpus emits a later one). [finish] does that in a
 * single top-down walk and hands back the completed function-scope records.
 */
internal class BlockTreeBuilder {
    private class Frame(val start: Address, val locals: List<Symbol>) {
        val children = mutableListOf<BlockScope>()
    }

    private val frames = mutableListOf<Frame>()
    private val roots = mutableListOf<BlockScope>()
    private var pending = mutableListOf<Symbol>()

    /** Address of the last N_RBRAC seen — the function's end when gcc omits the N_FUN end marker. */
    var lastClose: Address? = null
        private set

    fun local(record: Symbol) {
        pending += record
    }

    /** N_LBRAC: opens a scope owning the run of locals since the last bracket. */
    fun open(addr: Address) {
        frames += Frame(addr, claim())
    }

    /** N_RBRAC: closes the innermost scope into its parent. */
    fun close(addr: Address) {
        lastClose = addr
        // An unbalanced close can't own anything; leave its run pending to end up an orphan.
        val frame = frames.removeLastOrNull() ?: return
        val block = BlockScope(frame.start, addr, frame.locals + claim(), frame.children)
        (frames.lastOrNull()?.children ?: roots) += block
    }

    private fun claim() = pending.also { pending = mutableListOf() }

    /**
     * Resolve every block's source and return the finished tree plus the flat local list, the two
     * built from one walk so they can't disagree.
     *
     * A block's file is the one whose N_SLINEs in its *own* code (its range minus its children's)
     * carry the local's decl line, else the file of that own code when it is all one, else the
     * enclosing block's answer. Records no block claimed — gcc's `dbxout_reg_parms` emits register
     * parameters at depth 0 without setting `did_output`, so in a C++ function, whose depth-0 block
     * never owns variables, they trail with no N_LBRAC — belong to the function, like params.
     *
     * The record's own N_SOL says nothing: gcc emits the whole block tree from `dbxout_function_decl`
     * *after* the body, so every function-scope symbol carries whichever file the last line note in
     * the function happened to be in.
     */
    fun finish(lines: List<LineEntry>, functionSource: GhidraSourceFile): Pair<List<Symbol>, List<BlockScope>> {
        val flat = mutableListOf<Symbol>()

        // Rebuilds rather than repointing in place: the tree and the flat list hand out the *same*
        // corrected copies, so they cannot disagree, and a Symbol stays immutable — it is reachable
        // from BlockScope, from StabFunction.locals, and from maps keyed on either.
        fun BlockScope.attribute(inherited: GhidraSourceFile): BlockScope {
            val ownLines = lines.filter { entry ->
                entry.addr in start..<end && children.none { entry.addr in it.start..<it.end }
            }
            val blockSource = ownLines.map { it.source }.toSet().singleOrNull() ?: inherited
            val attributed = locals.map { local ->
                val sourcesAtLine = ownLines.filter { it.line == local.declLine }.map { it.source }.toSet()
                local.copy(sourceFile = sourcesAtLine.singleOrNull() ?: blockSource).also { flat += it }
            }
            return copy(
                locals = attributed,
                children = children.map { it.attribute(blockSource) },
                source = blockSource,
            )
        }

        val blocks = roots.map { it.attribute(functionSource) }
        pending.mapTo(flat) { it.copy(sourceFile = functionSource) }
        return flat to blocks
    }
}

/** Innermost lexical block covering [addr], or null when no block does (code outside every N_LBRAC). */
fun Func.blockAt(addr: Address) = blocks.firstNotNullOfOrNull { it.blockAt(addr) }

/**
 * Local `recordIndex` → the offset from [entry] at which its block opens. gcc's lexical scope *is*
 * the live range, which is what Ghidra's `firstUseOffset` wants: a register local declared from
 * entry claims the register for the whole function, so N inlined copies of the same name collapse
 * onto one variable and all but the first are dropped.
 */
fun Func.firstUseOffsets(entry: Address): Map<Int, Int> = buildMap {
    fun walk(blocks: List<BlockScope>) {
        for ((start, _, locals, children) in blocks) {
            val offset = (start.offset - entry.offset).toInt()
            locals.forEach { put(it.recordIndex, offset) }
            walk(children)
        }
    }
    walk(blocks)
}
