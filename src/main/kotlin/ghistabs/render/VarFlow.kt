package ghistabs.render

import ghidra.app.decompiler.DecompileResults
import ghidra.program.model.address.Address
import ghidra.program.model.pcode.HighLocal
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.VarnodeAST

/**
 * Where each decompiler variable of one function is written and read, keyed by instruction address.
 *
 * Read from the p-code syntax tree rather than the rendered text: a name in a statement doesn't say
 * whether that statement produced the value or consumed it, and that distinction is the whole point.
 * Names are the decompiler's own ([HighVariable.getName]), so they match what the render prints.
 */
class VarFlow(
    private val defs: Map<String, Set<Address>>,
    private val uses: Map<String, List<Address>>,
    private val slots: List<Slot> = emptyList(),
) {
    /** A decompiler variable as storage: where it lives, and from where it holds this value ([from]
     *  null when that is the whole function). */
    class Slot(val storage: Address, val from: Address?, val name: String)

    /**
     * What the decompiler calls whatever occupies [storage] at [pc] — the bridge from a stabs local,
     * which names a register or frame slot, to the name the render prints. Innermost wins: a register
     * local's first-use address is where its block opens, so the last one to open at or before [pc]
     * is the one live there, and a whole-function slot only stands in if none did.
     */
    fun nameAt(storage: Address, pc: Address) = slots
        .filter { it.storage == storage && (it.from == null || it.from <= pc) }
        .maxWithOrNull(compareBy(nullsFirst()) { it.from })
        ?.name

    /**
     * What an inlined stretch — the addresses [inside] accepts — takes from the code around it and
     * gives back: the variables it reads that something outside it wrote (its virtual arguments, in
     * first-read order) and those it writes that something outside it later reads (its virtual
     * results, in the order an assignment would read best — only one of them can be one).
     *
     * A guess, and knowingly a coarse one. `HighVariable`s merge SSA values, so "written outside" is
     * decided by address order: a def below the stretch's first read of that variable is a later
     * write of the same slot, not the argument.
     */
    fun crossing(inside: (Address) -> Boolean): Pair<List<String>, List<String>> {
        val args = uses.mapNotNull { (name, reads) ->
            val first = reads.firstOrNull(inside) ?: return@mapNotNull null
            val written = defs[name].orEmpty()
            // No def at all means a function input — a parameter, which is an argument by definition.
            first.takeIf { written.isEmpty() || written.any { d -> !inside(d) && d < first } }?.let { it to name }
        }
        val results = defs.mapNotNull { (name, writes) ->
            val last = writes.filter(inside).maxOrNull() ?: return@mapNotNull null
            uses[name].orEmpty().firstOrNull { !inside(it) && it > last }?.let { it to name }
        }
        return args.sortedBy { it.first }.map { it.second } to results.sortedBy { it.first }.map { it.second }
    }
}

/**
 * [VarFlow] for this decompilation. Constants and the decompiler's unnamed temporaries carry no
 * name to print, so they are no use as an argument and drop out.
 */
fun DecompileResults.varFlow(): VarFlow {
    val defs = mutableMapOf<String, MutableSet<Address>>()
    val uses = mutableMapOf<String, MutableList<Address>>()
    val high = highFunction ?: return VarFlow(emptyMap(), emptyMap())
    for (op in high.pcodeOps) {
        if (op.opcode in BOOKKEEPING) continue
        val at = op.seqnum.target
        (op.output as? VarnodeAST)?.named()?.let { defs.getOrPut(it) { mutableSetOf() } += at }
        op.inputs.mapNotNull { (it as? VarnodeAST)?.named() }.forEach { uses.getOrPut(it) { mutableListOf() } += at }
    }
    // Kept as storage rather than by holding the HighFunction: one is a handful of triples per
    // function, the other the whole p-code tree, and the render caches this for every function it
    // decompiles.
    val slots = high.localSymbolMap.symbols.asSequence().mapNotNull { sym ->
        sym.storage.minAddress?.let { VarFlow.Slot(it, sym.pcAddress, sym.name) }
    }.toList()
    return VarFlow(defs, uses.mapValues { (_, addrs) -> addrs.sorted() }, slots)
}

// Ops that record no computation the source performed. `INDIRECT` names every varnode a call might
// have touched, so unfiltered it made each stretch containing a call read every local in the frame —
// unpack's inlined `basic_string` calls came out with 30 arguments, the same 30 each time. A
// `MULTIEQUAL` is the decompiler's own phi node, and `CAST` only retypes what it is given.
private val BOOKKEEPING = setOf(PcodeOp.INDIRECT, PcodeOp.MULTIEQUAL, PcodeOp.CAST)

// Locals and parameters only (`HighParam` is a `HighLocal`). A `HighGlobal` is in scope wherever the
// inlined code landed and needs no passing; a `HighConstant` has no name to print; and `HighOther`
// covers the decompiler's own artefacts, among them varnodes it never prints — the x87 stack came out
// as `ar1`/`ar3`/`ar4`, names that appear in no view of the program.
private fun VarnodeAST.named() = (high as? HighLocal)?.name?.takeUnless { it.isBlank() }
