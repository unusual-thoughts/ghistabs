package ghistabs.cpp.recover

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.abi.CxxAbi
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/**
 * Each class's possible size range ([Long.MAX_VALUE] when unbounded above), from its non-virtual bases'
 * offsets ([bases]), its furthest vptr ([vptrs]) and its allocation sizes ([allocated]).
 *
 * A class is at least as large as its last vptr and each base's minimum. A base is at most as large as
 * the gap to the next base, or to the end of the class holding it.
 */
fun sizeBounds(
    bases: Map<ClassDecl, List<Pair<ClassDecl, Long>>>,
    vptrs: Map<ClassDecl, Long>,
    allocated: Map<ClassDecl, Long>,
    ptrSize: Long,
): Map<ClassDecl, LongRange> {
    val classes = bases.keys + vptrs.keys + allocated.keys
    val least = mutableMapOf<ClassDecl, Long>()
    fun atLeast(k: ClassDecl, depth: Int = 0): Long = least.getOrPut(k) {
        if (depth > MAX_DEPTH) return 0
        listOfNotNull(
            allocated[k],
            vptrs[k]?.plus(ptrSize),
            bases[k].orEmpty().maxOfOrNull { (b, at) -> at + atLeast(b, depth + 1) },
        ).maxOrNull() ?: 0
    }

    // Each base, as the classes holding it place it: from its offset to the next base's, or the holder's end.
    val holders = mutableMapOf<ClassDecl, MutableList<Pair<ClassDecl, Long?>>>()
    for ((holder, held) in bases) {
        val sorted = held.sortedBy { it.second }
        for ((b, at) in sorted) {
            val next = sorted.firstOrNull { it.second > at }?.second
            holders.getOrPut(b) { mutableListOf() } += holder to next?.minus(at)
        }
    }
    val most = mutableMapOf<ClassDecl, Long?>()
    fun atMost(k: ClassDecl, depth: Int = 0): Long? = if (k in most) {
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
 * Reads the sizes each class is allocated with: the `operator new(size)` result a constructor runs on,
 * found in the decompiled callers of [ctors].
 */
class NewSizeReader(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    fun read(ctors: Map<Function, ClassDecl>, monitor: TaskMonitor): Map<ClassDecl, Long> {
        val callers = ctors.keys.flatMapTo(mutableSetOf()) { it.getCallingFunctions(monitor) }
        val sizes = mutableMapOf<ClassDecl, MutableSet<Long>>()
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
            if (all.size > 1) debug("msvc-new-sizes", "${cls.name} allocated with sizes $all")
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
