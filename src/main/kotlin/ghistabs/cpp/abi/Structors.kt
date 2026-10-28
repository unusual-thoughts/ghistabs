package ghistabs.cpp.abi

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.pointerInto
import ghistabs.cpp.thisStorage
import ghistabs.diagnose.DiagnosticSink

/** What a function that stores a class's vptr is to that class. */
enum class StructorKind { CONSTRUCTOR, DESTRUCTOR, DELETING_DESTRUCTOR }

/**
 * What a function does to its `this`: the [classes] whose vftables it stores where they belong in it,
 * and whether it hands `this` back ([returnsThis]).
 */
data class VptrStores<K>(val classes: Set<K>, val returnsThis: Boolean)

/**
 * The class a function storing [classes]' vftables builds or tears down: the most derived of them,
 * which the others are bases of, inlined. Null for classes that are not one line of descent.
 */
fun <K> storedClass(classes: Set<K>, ancestors: (K) -> Set<K>): K? =
    classes.singleOrNull { c -> classes.all { it == c || it in ancestors(c) } }

/**
 * The constructors and destructors among the functions that store vptrs ([storers]), given the
 * functions vftable slots hold, the classes whose tables hold them ([holders]), and what each function
 * calls on its own `this` ([thisCalls]).
 *
 * A constructor is never virtual, so a slot function that runs a structor on its object is a deleting
 * destructor: one that stores its holders' vptr itself has the destructor inlined, and one that calls
 * a storer of theirs calls the destructor. That store can be a base's: a class whose destructor does
 * nothing before its base's leaves the store of its own vptr out. Telling the other storers apart takes
 * the ABI: under one whose constructors return `this` ([constructorsReturnThis]) the rest are
 * constructors if they do and destructors if they don't; under any other only the destructors a
 * deleting one calls are known.
 */
fun <K, F> structors(
    storers: Map<F, VptrStores<K>>,
    holders: Map<F, Set<K>>,
    thisCalls: (F) -> Set<F>,
    ancestors: (K) -> Set<K>,
    constructorsReturnThis: Boolean,
): Map<F, Pair<K, StructorKind>> {
    val owners = storers.mapNotNull { (f, s) -> storedClass(s.classes, ancestors)?.let { f to it } }.toMap()
    fun mayDestroy(f: F) = !constructorsReturnThis || storers[f]?.returnsThis != true

    // The holder whose deleting destructor a slot is, if it tears down a [cls] in the end: [cls] itself, or the
    // one class deriving from it that the others do too, whose own destructor the compiler left no vptr store in.
    fun deleting(held: Set<K>, cls: K): K? {
        val derived = held.filter { it == cls || cls in ancestors(it) }
        return derived.singleOrNull { c -> derived.all { it == c || c in ancestors(it) } }
    }
    val found = mutableMapOf<F, Pair<K, StructorKind>>()
    for ((slot, held) in holders) {
        val own = owners[slot]
        if (own != null) {
            deleting(held, own)?.let { found[slot] = it to StructorKind.DELETING_DESTRUCTOR }
            continue
        }
        val dtors = thisCalls(slot).filter(::mayDestroy).mapNotNull { f ->
            owners[f]?.let { cls -> deleting(held, cls)?.let { Triple(f, cls, it) } }
        }
        val (dtor, cls, holder) = dtors.singleOrNull() ?: continue
        found[slot] = holder to StructorKind.DELETING_DESTRUCTOR
        found.putIfAbsent(dtor, cls to StructorKind.DESTRUCTOR)
    }
    if (constructorsReturnThis) {
        for ((f, cls) in owners) {
            found.putIfAbsent(f, cls to if (mayDestroy(f)) StructorKind.DESTRUCTOR else StructorKind.CONSTRUCTOR)
        }
    }
    return found
}

/**
 * The vptr stores of every function that writes one of [tables], each a vftable's address and the
 * class and subobject offset it serves, and the functions each of those and of some others calls on its
 * own `this`. Off the decompiler: a store counts only through `this`, at the table's own offset, which
 * leaves out a local object built inline (on the stack, or fresh from `operator new`) and a member
 * object's table stored further in; a call, only with `this` for its first argument, which leaves out
 * a method building and destroying a local of a class it has nothing else to do with.
 */
class VptrStoreReader<K>(
    private val program: Program,
    private val tables: Map<Address, Pair<K, Long>>,
    sink: DiagnosticSink,
) : DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    class Reading<K>(val stores: Map<Function, VptrStores<K>>, val thisCalls: Map<Function, Set<Function>>)

    /** The storers' stores, and what they and [others] call on `this`. */
    fun read(others: Collection<Function>, monitor: TaskMonitor): Reading<K> {
        val writes = mutableMapOf<Function, MutableMap<Address, MutableList<Pair<K, Long>>>>()
        for ((table, served) in tables) {
            for (ref in program.referenceManager.getReferencesTo(table)) {
                val at = ref.fromAddress
                if (program.listing.getInstructionAt(at) == null) continue
                val func = program.functionManager.getFunctionContaining(at) ?: continue
                writes.getOrPut(func) { mutableMapOf() }.getOrPut(at) { mutableListOf() } += served
            }
        }
        if (writes.isEmpty() || thisStorage == null) return Reading(emptyMap(), emptyMap())
        val stores = mutableMapOf<Function, VptrStores<K>>()
        val thisCalls = mutableMapOf<Function, Set<Function>>()
        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
            for (func in writes.keys + others) {
                if (monitor.isCancelled) break
                val high = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
                if (high == null) {
                    debug("structor-undecompiled", func.name, func.entryPoint)
                    continue
                }
                writes[func]?.let { stores[func] = high.vptrStores(it) }
                thisCalls[func] = high.thisCalls()
            }
        } finally {
            decomp.dispose()
        }
        return Reading(stores, thisCalls)
    }

    private fun HighFunction.thisCalls() = pcodeOps.asSequence()
        .filter { it.opcode == PcodeOp.CALL && it.numInputs > 1 && it.getInput(1).thisOffset() == 0L }
        .mapNotNull { program.functionManager.getFunctionAt(it.getInput(0).address) }
        .mapTo(mutableSetOf()) { it.getThunkedFunction(true) ?: it }

    private fun HighFunction.vptrStores(at: Map<Address, List<Pair<K, Long>>>): VptrStores<K> {
        val classes = mutableSetOf<K>()
        var returnsThis = false
        for (op in pcodeOps.asSequence()) {
            when (op.opcode) {
                PcodeOp.STORE -> {
                    val served = at[op.seqnum.target] ?: continue
                    val offset = op.getInput(1).thisOffset() ?: continue
                    served.filter { it.second == offset }.mapTo(classes) { it.first }
                }

                PcodeOp.RETURN -> if (op.numInputs > 1 && op.getInput(1).thisOffset() == 0L) returnsThis = true
            }
        }
        return VptrStores(classes, returnsThis)
    }

    /** How far past `this` [this] points; null if it points into something else. */
    private fun Varnode.thisOffset() = pointerInto().takeIf { it.isThis(thisStorage) }?.offset

    private companion object {
        const val DECOMPILE_TIMEOUT_SECONDS = 30
    }
}
