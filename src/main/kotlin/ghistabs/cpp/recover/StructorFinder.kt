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
import ghistabs.cpp.abi.StructorRole.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/**
 * The [classes] whose vtables a function stores into `this` where they belong, and what it calls on `this` or a
 * subobject of it [before] the first of those stores and [after] the last.
 */
data class VptrStores(
    val classes: Set<ClassDecl>,
    val before: Set<Function> = emptySet(),
    val after: Set<Function> = emptySet(),
)

/** The class a function storing [classes]' vtables builds or destroys: the one the others are bases of, or null. */
fun storedClass(classes: Set<ClassDecl>): ClassDecl? =
    classes.singleOrNull { c -> classes.all { it == c || c.derivesFrom(it) } }

/**
 * What [StructorFinder.find] found: each structor's class and role ([roles]), each constructor a linker folded
 * into another class's that builds [folded] classes too, and the bytes each function read stores through
 * `this`.
 */
class Structors(
    val roles: Map<Function, Pair<ClassDecl, StructorRole>>,
    val folded: Map<Function, Set<ClassDecl>>,
    private val thisStores: Map<Function, Map<Int, Int>>,
) {
    /** Each constructor, by the class it builds. */
    val constructors = roles.filterValues { it.second == CONSTRUCTOR }.mapValues { it.value.first }

    /**
     * The bytes each class's constructors, its own and those folded into another's, store through `this`, by
     * offset into it: its own fields where nothing else is laid, and how large it is at least.
     */
    val constructorStores: Map<ClassDecl, Map<Int, Int>> by lazy {
        val built = constructors.map { (f, cls) -> f to cls } + folded.flatMap { (f, cs) -> cs.map { f to it } }
        buildMap<ClassDecl, MutableMap<Int, Int>> {
            for ((f, cls) in built) {
                val into = getOrPut(cls) { mutableMapOf() }
                thisStores[f].orEmpty().forEach { (at, size) -> into.merge(at, size, ::maxOf) }
            }
        }
    }
}

/** Finds constructors and destructors among [classes]' by the vtables they store into `this`, decompiled. */
class StructorFinder(private val program: Program, classes: Collection<ClassDecl>, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    private val tables = classes.vptrTables(program)

    /**
     * Each structor's class and role, given [slots]: each vtable slot's function, and the classes holding it.
     * A base with no vtable to store is built by the one function each of its deriving class's constructors
     * calls on its subobject ([baseConstructors]).
     */
    fun find(slots: Map<Function, Set<ClassDecl>>, convention: StructorConvention, monitor: TaskMonitor): Structors {
        val reading = read(slots.keys, monitor)
        val roles = reading.roles(slots, convention).toMutableMap()
        val subobjectCalls = reading.subobjectCalls.toMutableMap()
        val thisStores = reading.thisStores.toMutableMap()
        val folded = mutableMapOf<Function, MutableSet<ClassDecl>>()
        var built = roles.filterValues { (_, role) -> role == CONSTRUCTOR }
        while (built.isNotEmpty() && !monitor.isCancelled) {
            val found = mutableMapOf<Function, ClassDecl>()
            for ((cls, ctor) in baseConstructors(built, subobjectCalls)) {
                val taken = roles[ctor]?.first ?: found[ctor]
                when {
                    taken == null -> found[ctor] = cls
                    taken != cls -> folded.getOrPut(ctor) { mutableSetOf() } += cls
                }
            }
            roles += found.mapValues { (_, cls) -> cls to CONSTRUCTOR }
            val more = decompile(found.keys, emptyMap(), monitor)
            subobjectCalls += more.subobjectCalls
            thisStores += more.thisStores
            built = found.mapValues { (_, cls) -> cls to CONSTRUCTOR }
        }
        return Structors(roles, folded, thisStores)
    }

    /**
     * The constructor of each base of [ctors]' classes that has no vtable, so stores none: the one function
     * a constructor calls on that base's subobject, which [subobjectCalls] holds by offset into `this`.
     */
    private fun baseConstructors(
        ctors: Map<Function, Pair<ClassDecl, StructorRole>>,
        subobjectCalls: Map<Function, Map<Long, Set<Function>>>,
    ): Map<ClassDecl, Function> = buildMap {
        for ((ctor, built) in ctors) {
            val calls = subobjectCalls[ctor].orEmpty()
            for (base in built.first.bases) {
                if (base.isVirtual || base.cls.vftables.isNotEmpty()) continue
                val callee = base.offset?.let(calls::get)?.singleOrNull() ?: continue
                putIfAbsent(base.cls, callee)
            }
        }
    }

    /**
     * The vptrs each function stores ([stores]), the functions each calls on `this` or a subobject of it, by
     * offset into it ([subobjectCalls]), and the bytes each stores through `this`, by offset ([thisStores]).
     */
    class Reading(
        val stores: Map<Function, VptrStores>,
        val subobjectCalls: Map<Function, Map<Long, Set<Function>>>,
        val thisStores: Map<Function, Map<Int, Int>> = emptyMap(),
    ) {
        /** The functions each calls on `this` itself. */
        private val thisCalls = subobjectCalls.mapValues { (_, calls) -> calls[0L].orEmpty() }

        /** The class a slot held by [held] deletes when it destroys a [cls]: [cls], or the one most derived. */
        private fun deleting(held: Set<ClassDecl>, cls: ClassDecl): ClassDecl? {
            val derived = held.filter { it == cls || it.derivesFrom(cls) }
            return derived.singleOrNull { c -> derived.all { it == c || it.derivesFrom(c) } }
        }

        /**
         * A constructor is never virtual, so a slot that stores vptrs, or calls a function that does,
         * destroys: a deleting destructor if it frees `this`, and the function it calls the destructor. The
         * other storers go by their calls ([sortByCalls]), as `RecoverClassesFromRTTIScript` sorts them.
         */
        fun roles(
            slots: Map<Function, Set<ClassDecl>>,
            convention: StructorConvention,
        ): Map<Function, Pair<ClassDecl, StructorRole>> = buildMap {
            val owners = stores.mapNotNull { (f, s) -> storedClass(s.classes)?.let { f to it } }.toMap()

            for ((slot, held) in slots) {
                val own = owners[slot]
                when {
                    // Itanium's vtable holds the complete object destructor too, which frees nothing.
                    !frees(slot, convention) -> own?.let { this[slot] = it to DESTRUCTOR }

                    own != null -> deleting(held, own)?.let { this[slot] = it to DELETING_DESTRUCTOR }

                    else -> {
                        val (dtor, cls, holder) = thisCalls[slot].orEmpty().mapNotNull { f ->
                            owners[f]?.let { cls -> deleting(held, cls)?.let { Triple(f, cls, it) } }
                        }.singleOrNull() ?: unstoredDestructor(slot, held, owners, convention) ?: continue
                        this[slot] = holder to DELETING_DESTRUCTOR
                        putIfAbsent(dtor, cls to DESTRUCTOR)
                    }
                }
            }
            sortByCalls(owners)
        }

        /**
         * Sorts the storers of [owners]' vptrs left, until no more sort. A constructor builds its bases before
         * storing its vptr, and a destructor destroys them after, so a storer calling a base's storer before
         * its stores builds, and one calling it only after destroys; that base's storer, and what a destructor
         * calls on `this`, take the same role. A storer calling known constructors and no destructor builds, and
         * the reverse destroys. Every storer left builds.
         */
        private fun MutableMap<Function, Pair<ClassDecl, StructorRole>>.sortByCalls(owners: Map<Function, ClassDecl>) {
            fun basesOf(cls: ClassDecl, fs: Set<Function>?, not: StructorRole) = fs.orEmpty().filter { g ->
                owners[g]?.let { it != cls && cls.derivesFrom(it) } == true && this[g]?.second != not
            }
            do {
                val known = size
                for ((f, cls) in owners) {
                    if (f in this) continue
                    val order = stores.getValue(f)
                    val role = when {
                        basesOf(cls, order.before, DESTRUCTOR).isNotEmpty() -> CONSTRUCTOR
                        basesOf(cls, order.after, CONSTRUCTOR).isNotEmpty() -> DESTRUCTOR
                        else -> byKnownCalls(f)
                    }
                    role?.let { this[f] = cls to it }
                }
                for ((f, entry) in toList()) {
                    val (cls, role) = entry
                    val bases = when (role) {
                        CONSTRUCTOR -> basesOf(cls, stores[f]?.before, DESTRUCTOR)
                        DESTRUCTOR -> basesOf(cls, thisCalls[f].orEmpty() + stores[f]?.after.orEmpty(), CONSTRUCTOR)
                        else -> emptyList()
                    }
                    for (g in bases) putIfAbsent(g, owners.getValue(g) to role)
                }
            } while (size != known)
            for ((f, cls) in owners) putIfAbsent(f, cls to CONSTRUCTOR)
        }

        /** [CONSTRUCTOR] if [f] calls known constructors and no destructor, [DESTRUCTOR] for the reverse. */
        private fun Map<Function, Pair<ClassDecl, StructorRole>>.byKnownCalls(f: Function): StructorRole? {
            val roles = subobjectCalls[f].orEmpty().values.flatten().mapNotNullTo(mutableSetOf()) { this[it]?.second }
            return when {
                CONSTRUCTOR in roles && DESTRUCTOR !in roles -> CONSTRUCTOR
                DESTRUCTOR in roles && CONSTRUCTOR !in roles -> DESTRUCTOR
                else -> null
            }
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
        ): Triple<Function, ClassDecl, ClassDecl>? = when (
            val dtor = thisCalls[slot].orEmpty().singleOrNull { it.name !in convention.operatorDeleteNames }
        ) {
            null, in owners, slot -> null
            else -> virtualOwner(held)?.let { Triple(dtor, it, it) }
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
        if (writes.isEmpty()) return Reading(emptyMap(), emptyMap())
        return decompile(writes.keys + others, writes, monitor)
    }

    /** What [funcs] store and call through `this`, decompiled, and which of [writes]' vptrs each stores. */
    private fun decompile(
        funcs: Collection<Function>,
        writes: Map<Function, Map<Address, List<Pair<ClassDecl, Long>>>>,
        monitor: TaskMonitor,
    ): Reading {
        val stores = mutableMapOf<Function, VptrStores>()
        val subobjectCalls = mutableMapOf<Function, Map<Long, Set<Function>>>()
        val thisStores = mutableMapOf<Function, Map<Int, Int>>()
        if (thisStorage != null) {
            DecompInterface().useWith(program) { decomp ->
                for (func in funcs) {
                    val high = decomp.decompiled(func, monitor) ?: continue
                    writes[func]?.let { stores[func] = high.vptrStores(it) }
                    subobjectCalls[func] = high.subobjectCalls()
                    thisStores[func] = high.thisStores()
                }
            }
        }
        return Reading(stores, subobjectCalls, thisStores)
    }

    private fun DecompInterface.decompiled(func: Function, monitor: TaskMonitor): HighFunction? {
        if (monitor.isCancelled) return null
        return decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
            ?: null.also { debug("structor-undecompiled", func.name, func.entryPoint) }
    }

    /** The bytes this stores through `this`, by offset into it: the larger store where two meet. */
    private fun HighFunction.thisStores(): Map<Int, Int> = buildMap {
        for (op in pcodeOps) {
            if (op.opcode != PcodeOp.STORE) continue
            val at = op.getInput(1).thisOffset() ?: continue
            merge(at.toInt(), op.getInput(2).size, ::maxOf)
        }
    }

    /** The functions this calls with a pointer into `this` first, by how far into it. */
    private fun HighFunction.subobjectCalls(): Map<Long, Set<Function>> = pcodeOps.asSequence()
        .mapNotNull { subobjectCall(it) }
        .groupBy({ it.first }, { it.second }).mapValues { (_, fs) -> fs.toSet() }

    /** The function [op] calls with a pointer into `this` first, and how far into it; null if it's no such call. */
    private fun subobjectCall(op: PcodeOp): Pair<Long, Function>? {
        if (op.opcode != PcodeOp.CALL || op.numInputs < 2) return null
        val at = op.getInput(1).thisOffset() ?: return null
        val callee = program.functionManager.getFunctionAt(op.getInput(0).address) ?: return null
        return at to (callee.getThunkedFunction(true) ?: callee)
    }

    /** Which of the vptrs [at] holds this stores, and what it calls on `this` before and after, by address. */
    private fun HighFunction.vptrStores(at: Map<Address, List<Pair<ClassDecl, Long>>>): VptrStores {
        val classes = mutableSetOf<ClassDecl>()
        val storedAt = mutableListOf<Address>()
        val calls = mutableListOf<Pair<Address, Function>>()
        for (op in pcodeOps) {
            subobjectCall(op)?.let { calls += op.seqnum.target to it.second }
            if (op.opcode != PcodeOp.STORE) continue
            val served = at[op.seqnum.target] ?: continue
            val offset = op.getInput(1).thisOffset() ?: continue
            val hit = served.filter { it.second == offset }.map { it.first }
            if (hit.isEmpty()) continue
            classes += hit
            storedAt += op.seqnum.target
        }
        val first = storedAt.minOrNull() ?: return VptrStores(classes)
        val last = storedAt.max()
        return VptrStores(
            classes,
            before = calls.filter { it.first < first }.mapTo(mutableSetOf()) { it.second },
            after = calls.filter { it.first > last }.mapTo(mutableSetOf()) { it.second },
        )
    }

    /** How far past `this` [this] points; null if it points into something else. */
    private fun Varnode.thisOffset() = pointerInto().takeIf { it.isThis(thisStorage) }?.offset
}
