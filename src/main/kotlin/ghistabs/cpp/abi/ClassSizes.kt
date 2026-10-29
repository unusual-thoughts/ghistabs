package ghistabs.cpp.abi

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.pointerInto
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/**
 * The sizes each class, by its type descriptor, can be, from the least to the most ([Long.MAX_VALUE] where nothing bounds it),
 * from where its non-virtual direct bases sit in it ([bases], by offset), the furthest vptr in it
 * ([vptrs]), and the sizes it is allocated with ([allocated]).
 *
 * A class reaches at least past its last vptr and each base's own least size, and a base reaches at
 * most up to the next base of the class that holds it, or that class's end, which bounds it from above:
 * the bases of a class are laid out one after another, and none overlaps the next. When the two bounds
 * meet, that is its size.
 */
fun sizeBounds(
    bases: Map<Address, List<Pair<Address, Long>>>,
    vptrs: Map<Address, Long>,
    allocated: Map<Address, Long>,
    ptrSize: Long,
): Map<Address, LongRange> {
    val classes = bases.keys + vptrs.keys + allocated.keys
    val least = mutableMapOf<Address, Long>()
    fun atLeast(k: Address, depth: Int = 0): Long = least.getOrPut(k) {
        if (depth > MAX_DEPTH) return 0
        listOfNotNull(
            allocated[k],
            vptrs[k]?.plus(ptrSize),
            bases[k].orEmpty().maxOfOrNull { (b, at) -> at + atLeast(b, depth + 1) },
        ).maxOrNull() ?: 0
    }

    // Each base, as the classes holding it place it: from its offset to the next base's, or the holder's end.
    val holders = mutableMapOf<Address, MutableList<Pair<Address, Long?>>>()
    for ((holder, held) in bases) {
        val sorted = held.sortedBy { it.second }
        for ((b, at) in sorted) {
            val next = sorted.firstOrNull { it.second > at }?.second
            holders.getOrPut(b) { mutableListOf() } += holder to next?.minus(at)
        }
    }
    val most = mutableMapOf<Address, Long?>()
    fun atMost(k: Address, depth: Int = 0): Long? = if (k in most) {
        most[k]
    } else {
        val bounds = holders[k].orEmpty().mapNotNull { (holder, room) ->
            room ?: run {
                val end = allocated[holder] ?: atMost(holder, depth + 1).takeIf { depth < MAX_DEPTH }
                val at = bases.getValue(holder).first { it.first == k }.second
                end?.minus(at)
            }
        }
        (listOfNotNull(allocated[k]) + bounds).minOrNull().also { most[k] = it }
    }

    return classes.associateWith { k ->
        allocated[k]?.let { it..it } ?: atLeast(k)..(atMost(k) ?: Long.MAX_VALUE)
    }
}

private const val MAX_DEPTH = 64

/**
 * The sizes each class is allocated with: an `operator new(size)` whose result one of the class's
 * constructors ([ctors]) runs on, off each constructor's callers' decompilation, `operator new` going by
 * one of [abi]'s [CxxAbi.operatorNewNames].
 */
class NewSizeReader(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    fun read(ctors: Map<Function, Address>, monitor: TaskMonitor): Map<Address, Long> {
        val callers = ctors.keys.flatMapTo(mutableSetOf()) { it.getCallingFunctions(monitor) }
        val sizes = mutableMapOf<Address, MutableSet<Long>>()
        DecompInterface().useWith(program) { decomp ->
            for (f in callers) {
                if (monitor.isCancelled) break
                val high = decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction ?: continue
                for (op in high.pcodeOps.asSequence()) {
                    val cls = op.callee()?.let(ctors::get) ?: continue
                    val alloc = op.getInput(1).pointerInto().takeIf { it.offset == 0L }?.root?.def ?: continue
                    val size = alloc.getInput(1)?.takeIf { alloc.callee()?.isOperatorNew() == true && it.isConstant }
                    size?.let { sizes.getOrPut(cls) { mutableSetOf() } += it.offset }
                }
            }
        }
        return sizes.mapValues { (cls, all) ->
            if (all.size > 1) debug("msvc-new-sizes", "$cls allocated with sizes $all")
            all.max()
        }
    }

    private fun PcodeOp.callee(): Function? {
        if (opcode != PcodeOp.CALL || numInputs < 2) return null
        val f = program.functionManager.getFunctionAt(getInput(0).address) ?: return null
        return f.getThunkedFunction(true) ?: f
    }

    private fun Function.isOperatorNew() = name in abi.operatorNewNames

    private companion object {
        const val DECOMPILE_TIMEOUT_SECONDS = 30
    }
}
