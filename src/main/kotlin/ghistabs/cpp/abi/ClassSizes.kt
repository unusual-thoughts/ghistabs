package ghistabs.cpp.abi

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.pointerInto
import ghistabs.diagnose.DiagnosticSink

/**
 * What is known of a class's size: [exact], from an `operator new` its constructor runs on, or the
 * object's own bounds, [atLeast] and [atMost].
 */
data class SizeBounds(val atLeast: Long, val atMost: Long?, val exact: Long?) {
    /** The size to give the class's struct: the exact one, or as much as is sure. */
    val size get() = exact ?: atLeast
}

/**
 * The description of a class struct whose size [SizeBounds] found: [EXACT], which a reader may take as
 * the class's `sizeof`, or [AT_LEAST], a floor it may grow past.
 */
object SizedStruct {
    const val EXACT = "Size from `operator new` and the RTTI"
    const val AT_LEAST = "At least as large as the RTTI says its vptrs and bases reach"
}

/**
 * Each class's [SizeBounds], from where its non-virtual direct bases sit in it ([bases], by offset),
 * the furthest vptr in it ([vptrs]), and the sizes it is allocated with ([allocated]).
 *
 * A class reaches at least past its last vptr and each base's own least size, and a base reaches at
 * most up to the next base of the class that holds it, or that class's end, which bounds it from above:
 * the bases of a class are laid out one after another, and none overlaps the next. When the two bounds
 * meet, that is its size.
 */
fun <K> sizeBounds(
    bases: Map<K, List<Pair<K, Long>>>,
    vptrs: Map<K, Long>,
    allocated: Map<K, Long>,
    ptrSize: Long,
): Map<K, SizeBounds> {
    val classes = bases.keys + vptrs.keys + allocated.keys
    val least = mutableMapOf<K, Long>()
    fun atLeast(k: K, depth: Int = 0): Long = least.getOrPut(k) {
        if (depth > MAX_DEPTH) return 0
        listOfNotNull(
            allocated[k],
            vptrs[k]?.plus(ptrSize),
            bases[k].orEmpty().maxOfOrNull { (b, at) -> at + atLeast(b, depth + 1) },
        ).maxOrNull() ?: 0
    }

    // Each base, as the classes holding it place it: from its offset to the next base's, or the holder's end.
    val holders = mutableMapOf<K, MutableList<Pair<K, Long?>>>()
    for ((holder, held) in bases) {
        val sorted = held.sortedBy { it.second }
        for ((b, at) in sorted) {
            val next = sorted.firstOrNull { it.second > at }?.second
            holders.getOrPut(b) { mutableListOf() } += holder to next?.minus(at)
        }
    }
    val most = mutableMapOf<K, Long?>()
    fun atMost(k: K, depth: Int = 0): Long? = if (k in most) {
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
        val lo = atLeast(k)
        val hi = atMost(k)
        SizeBounds(lo, hi, allocated[k] ?: hi?.takeIf { it == lo })
    }
}

private const val MAX_DEPTH = 64

/**
 * The sizes each class is allocated with: an `operator new(size)` whose result one of the class's
 * constructors ([ctors]) runs on, off each constructor's callers' decompilation. Not `new[]`, whose
 * size is a count's worth and a cookie.
 */
class NewSizeReader<K>(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    fun read(ctors: Map<Function, K>, monitor: TaskMonitor): Map<K, Long> {
        val callers = ctors.keys.flatMapTo(mutableSetOf()) { it.getCallingFunctions(monitor) }
        val sizes = mutableMapOf<K, MutableSet<Long>>()
        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
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
        } finally {
            decomp.dispose()
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

    private fun Function.isOperatorNew() = name in OPERATOR_NEW

    private companion object {
        const val DECOMPILE_TIMEOUT_SECONDS = 30

        // As Ghidra's demangler names `??2@YAPAXI@Z` and its 64-bit twin, or the mangled name itself.
        val OPERATOR_NEW = setOf("operator_new", "operator new", "??2@YAPAXI@Z", "??2@YAPEAX_K@Z")
    }
}
