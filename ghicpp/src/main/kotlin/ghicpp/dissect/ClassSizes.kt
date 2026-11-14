package ghicpp.dissect

import ghicpp.ClassDecl
import ghicpp.abi.CxxAbi
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
import ghidrakt.alignedTo
import ghidrakt.diagnose.DiagnosticSink

/**
 * Each class's possible size range ([Long.MAX_VALUE] when unbounded above), from its non-virtual bases'
 * offsets, its furthest vptr ([vptrs]), the end of the furthest store its constructors make ([stored])
 * and its allocation sizes ([allocated]).
 *
 * A class is at least as large as its last vptr and each base's minimum, its virtual bases' included: each
 * virtual base takes a byte at least, past its offset ([ClassDecl.vbaseOffsets]), even one no class is known
 * for. A class whose virtual bases' offsets no record states lays them out past its non-virtual part, which
 * fills the gap the classes holding it leave it. A class with a vptr or virtual bases is pointer-aligned, so
 * its size is a whole number of pointers. A base is at most as large as the gap to the next base, or to the
 * end of the class holding it; but for a base with virtual bases, which that gap holds the non-virtual part
 * of alone.
 */
fun sizeBounds(
    classes: Collection<ClassDecl>,
    vptrs: Map<ClassDecl, Long>,
    allocated: Map<ClassDecl, Long>,
    ptrSize: Long,
    stored: Map<ClassDecl, Long> = emptyMap(),
): Map<ClassDecl, LongRange> {
    val placed = classes.associateWith { cls ->
        cls.bases.filterNot { it.isVirtual }.mapNotNull { b -> b.offset?.let { b.cls to it } }
    }
    // Each base, as the classes holding it place it: from its offset to the next base's, or the holder's end.
    val holders = mutableMapOf<ClassDecl, MutableList<Pair<ClassDecl, Long?>>>()
    for ((holder, held) in placed) {
        val sorted = held.sortedBy { it.second }
        for ((b, at) in sorted) {
            val next = sorted.firstOrNull { it.second > at }?.second
            holders.getOrPut(b) { mutableListOf() } += holder to next?.minus(at)
        }
    }

    val dynamic = mutableMapOf<ClassDecl, Boolean>()
    fun isDynamic(k: ClassDecl, depth: Int = 0): Boolean = dynamic.getOrPut(k) {
        depth <= MAX_DEPTH && (
            k in vptrs || k.hasVirtualBases || placed[k].orEmpty().any { (b, _) -> isDynamic(b, depth + 1) }
            )
    }

    val least = mutableMapOf<ClassDecl, Long>()
    fun atLeast(k: ClassDecl, depth: Int = 0): Long = least.getOrPut(k) {
        if (depth > MAX_DEPTH) return 0
        fun vbaseLeast(v: ClassDecl) = maxOf(1, atLeast(v, depth + 1))
        val nonVirtual = listOfNotNull(
            vptrs[k]?.plus(ptrSize),
            stored[k],
            placed[k].orEmpty().maxOfOrNull { (b, at) -> at + atLeast(b, depth + 1) },
        ).maxOrNull() ?: 0
        val vbases = k.allVirtualBases
        val pastVbases = if (k.nonVirtualSize == null && vbases.isNotEmpty()) {
            // Laid out past the non-virtual part, which fills what its holders leave it.
            val room = holders[k].orEmpty().mapNotNull { it.second }.minOrNull() ?: 0
            vbases.fold(maxOf(nonVirtual, room)) { at, v -> at.alignedTo(ptrSize) + vbaseLeast(v.cls) }
        } else {
            val named = vbases.mapNotNull { v -> v.offset?.plus(vbaseLeast(v.cls)) }
            (named + k.vbaseOffsets.map { it + 1 }).maxOrNull()
        }
        val size = listOfNotNull(allocated[k], nonVirtual, pastVbases).max()
        if (isDynamic(k)) size.alignedTo(ptrSize) else size
    }

    val most = mutableMapOf<ClassDecl, Long?>()
    fun atMost(k: ClassDecl, depth: Int = 0): Long? = if (k in most) {
        most[k]
    } else {
        val bounds = holders[k].orEmpty().takeUnless { k.hasVirtualBases }.orEmpty().mapNotNull { (holder, room) ->
            room ?: run {
                val end = allocated[holder] ?: atMost(holder, depth + 1).takeIf { depth < MAX_DEPTH }
                val at = placed.getValue(holder).first { it.first == k }.second
                end?.minus(at)
            }
        }
        (listOfNotNull(allocated[k]) + bounds).minOrNull().also { most[k] = it }
    }

    return (classes + vptrs.keys + allocated.keys).associateWith { k ->
        allocated[k]?.let { it..it } ?: atLeast(k)..(atMost(k) ?: Long.MAX_VALUE)
    }
}

/** Each class's furthest vptr, off its [ClassDecl.vftables]; none for a class whose vftables don't say. */
fun vptrOffsets(classes: Collection<ClassDecl>, program: Program): Map<ClassDecl, Long> =
    classes.mapNotNull { cls -> cls.vftables.mapNotNull { it.vfptrOffset(program) }.maxOrNull()?.let { cls to it } }
        .toMap()

private const val MAX_DEPTH = 64

/**
 * Reads the sizes each class is allocated with: the `operator new(size)` result a constructor runs on,
 * found in the decompiled callers of [ctors].
 */
class AllocationSizeFinder(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    fun read(ctors: Map<Function, ClassDecl>, monitor: TaskMonitor): Map<ClassDecl, Long> {
        monitor.message = "Finding constructors' callers"
        val callers = ctors.keys.flatMapTo(mutableSetOf()) { it.getCallingFunctions(monitor) }
        val sizes = mutableMapOf<ClassDecl, MutableSet<Long>>()
        program.decompileEach(callers, monitor, "Decompiling constructors' callers for allocation sizes") { _, high ->
            for (op in high.pcodeOps.asSequence()) {
                val cls = op.callee()?.let(ctors::get) ?: continue
                val obj = op.getInput(1).pointerInto()?.takeIf { it.offset == 0L } ?: continue
                val alloc = obj.root.instances.mapNotNull { it.def }.firstOrNull { it.isOperatorNew() }
                val size = alloc?.getInput(1)?.takeIf { it.isConstant }
                size?.let { sizes.getOrPut(cls) { mutableSetOf() } += it.offset }
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

    private fun PcodeOp.isOperatorNew() = callee()?.name in abi.operatorNewNames
}
