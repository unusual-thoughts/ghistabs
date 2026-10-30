package ghistabs.cpp.recover

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.abi.StructorConvention
import ghistabs.cpp.abi.StructorRole
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/** The [classes] whose vtables a function stores into `this` where they belong, and whether it returns `this`. */
data class VptrStores(val classes: Set<ClassDecl>, val returnsThis: Boolean)

/** The class a function storing [classes]' vtables builds or destroys: the one the others are bases of, or null. */
fun storedClass(classes: Set<ClassDecl>): ClassDecl? =
    classes.singleOrNull { c -> classes.all { it == c || c.derivesFrom(it) } }

/** Finds constructors and destructors among [classes]' by the vtables they store into `this`, decompiled. */
class StructorFinder(private val program: Program, classes: Collection<ClassDecl>, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    // Each vtable, by its address point: the class it serves and where in that class's object its vptr sits.
    private val tables = classes.flatMap { cls ->
        cls.vftables.mapNotNull { r -> r.vfptrOffset(program)?.let { r.addressPoint to (cls to it) } }
    }.toMap()

    /** Each structor's class and role, given [slots]: each vtable slot's function, and the classes holding it. */
    fun find(slots: Map<Function, Set<ClassDecl>>, convention: StructorConvention, monitor: TaskMonitor) =
        read(slots.keys, monitor).roles(slots, convention)

    /** The vptrs each function stores ([stores]), and the functions each calls on `this`. */
    class Reading(val stores: Map<Function, VptrStores>, val thisCalls: Map<Function, Set<Function>>) {
        /**
         * A constructor is never virtual, so a slot that stores vptrs, or calls a function that does,
         * destroys: a deleting destructor if it frees `this`, and the function it calls the destructor.
         * Where constructors return `this`, that sorts the other storers. Where they don't, a storer a
         * destructor calls on `this` destroys too, a base's destructor, and every storer left builds.
         */
        fun roles(
            slots: Map<Function, Set<ClassDecl>>,
            convention: StructorConvention,
        ): Map<Function, Pair<ClassDecl, StructorRole>> = buildMap {
            val returnsThis = convention.constructorsReturnThis
            val owners = stores.mapNotNull { (f, s) -> storedClass(s.classes)?.let { f to it } }.toMap()
            fun mayDestroy(f: Function) = !returnsThis || stores[f]?.returnsThis != true

            // The class a slot held by [held] deletes when it destroys a [cls]: [cls], or the one most derived.
            fun deleting(held: Set<ClassDecl>, cls: ClassDecl): ClassDecl? {
                val derived = held.filter { it == cls || it.derivesFrom(cls) }
                return derived.singleOrNull { c -> derived.all { it == c || it.derivesFrom(c) } }
            }
            for ((slot, held) in slots) {
                val own = owners[slot]
                when {
                    // Itanium's vtable holds the complete object destructor too, which frees nothing.
                    !frees(slot, convention) -> own?.let { this[slot] = it to StructorRole.DESTRUCTOR }

                    own != null -> deleting(held, own)?.let { this[slot] = it to StructorRole.DELETING_DESTRUCTOR }

                    else -> {
                        val stored = thisCalls[slot].orEmpty().filter(::mayDestroy).mapNotNull { f ->
                            owners[f]?.let { cls -> deleting(held, cls)?.let { Triple(f, cls, it) } }
                        }.singleOrNull()
                        (stored ?: unstoredDestructor(slot, held, owners, convention))?.let { (dtor, cls, holder) ->
                            this[slot] = holder to StructorRole.DELETING_DESTRUCTOR
                            putIfAbsent(dtor, cls to StructorRole.DESTRUCTOR)
                        }
                    }
                }
            }
            if (returnsThis) {
                for ((f, cls) in owners) {
                    putIfAbsent(f, cls to if (mayDestroy(f)) StructorRole.DESTRUCTOR else StructorRole.CONSTRUCTOR)
                }
            } else {
                sortByCalls(owners)
            }
        }

        /** Makes each storer a destructor calls on `this` a destructor too, and every other one a constructor. */
        private fun MutableMap<Function, Pair<ClassDecl, StructorRole>>.sortByCalls(owners: Map<Function, ClassDecl>) {
            var destroying = keys.toList()
            while (destroying.isNotEmpty()) {
                destroying = destroying.flatMap { thisCalls[it].orEmpty() }.filter { it !in this && it in owners }
                    .distinct()
                for (f in destroying) this[f] = owners.getValue(f) to StructorRole.DESTRUCTOR
            }
            for ((f, cls) in owners) putIfAbsent(f, cls to StructorRole.CONSTRUCTOR)
        }

        /**
         * The destructor a deleting destructor [slot] calls where that stores no vptr, as one whose vptr
         * resets the compiler dropped for the bases' destructors' own: the one other function it calls on
         * `this`, destroying the class that introduced the slot ([virtualOwner]).
         */
        private fun unstoredDestructor(
            slot: Function,
            held: Set<ClassDecl>,
            owners: Map<Function, ClassDecl>,
            convention: StructorConvention,
        ): Triple<Function, ClassDecl, ClassDecl>? {
            val dtor = thisCalls[slot].orEmpty().filter { it.name !in convention.operatorDeleteNames }.singleOrNull()
            if (dtor == null || dtor in owners || dtor == slot) return null
            return virtualOwner(held)?.let { Triple(dtor, it, it) }
        }

        private fun frees(f: Function, convention: StructorConvention) =
            thisCalls[f].orEmpty().any { it.name in convention.operatorDeleteNames }
    }

    /**
     * The stores of each function writing one of [tables], and what those and [others] call on `this`. A
     * store counts only through `this` at the table's own offset, which leaves out locals built inline and
     * member objects; a call, only with `this` first, which leaves out a local built and destroyed.
     */
    private fun read(others: Collection<Function>, monitor: TaskMonitor): Reading {
        val writes = buildMap {
            for ((table, served) in tables) {
                for (ref in program.referenceManager.getReferencesTo(table)) {
                    val at = ref.fromAddress
                    if (program.listing.getInstructionAt(at) == null) continue
                    val func = program.functionManager.getFunctionContaining(at) ?: continue
                    getOrPut(func) { mutableMapOf() }.getOrPut(at) { mutableListOf() } += served
                }
            }
        }
        if (writes.isEmpty() || thisStorage == null) return Reading(emptyMap(), emptyMap())
        val stores = mutableMapOf<Function, VptrStores>()
        val thisCalls = mutableMapOf<Function, Set<Function>>()
        DecompInterface().useWith(program) { decomp ->
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
        }
        return Reading(stores, thisCalls)
    }

    private fun HighFunction.thisCalls() = pcodeOps.asSequence()
        .filter { it.opcode == PcodeOp.CALL && it.numInputs > 1 && it.getInput(1).thisOffset() == 0L }
        .mapNotNull { program.functionManager.getFunctionAt(it.getInput(0).address) }
        .mapTo(mutableSetOf()) { it.getThunkedFunction(true) ?: it }

    private fun HighFunction.vptrStores(at: Map<Address, List<Pair<ClassDecl, Long>>>): VptrStores {
        val classes = mutableSetOf<ClassDecl>()
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
