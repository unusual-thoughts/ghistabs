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

/** The [classes] whose vtables a function stores into `this` where they belong, and whether it returns `this`. */
data class VptrStores(val classes: Set<ClassDecl>, val returnsThis: Boolean)

/** The class a function storing [classes]' vtables builds or destroys: the one the others are bases of, or null. */
fun storedClass(classes: Set<ClassDecl>): ClassDecl? =
    classes.singleOrNull { c -> classes.all { it == c || c.derivesFrom(it) } }

/** Finds constructors and destructors among [classes]' by the vtables they store into `this`, decompiled. */
class StructorFinder(private val program: Program, classes: Collection<ClassDecl>, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    /** Each vtable, by its address point: the class it serves and where in that class's object its vptr sits. */
    private val tables = classes.flatMap { cls ->
        cls.vftables.mapNotNull { r -> r.vfptrOffset(program)?.let { r.addressPoint to (cls to it) } }
    }.toMap()

    /**
     * Each base whose constructor [find] gave another class, the two folded into one function, as a linker
     * folds identical code: it builds this one too.
     */
    val foldedBaseConstructors = mutableMapOf<ClassDecl, Function>()

    /**
     * Each structor's class and role, given [slots]: each vtable slot's function, and the classes holding it.
     * A base with no vtable to store is built by the one function each of its deriving class's constructors
     * calls on its subobject ([baseConstructors]).
     */
    fun find(
        slots: Map<Function, Set<ClassDecl>>,
        convention: StructorConvention,
        monitor: TaskMonitor,
    ): Map<Function, Pair<ClassDecl, StructorRole>> {
        val reading = read(slots.keys, monitor)
        val roles = reading.roles(slots, convention).toMutableMap()
        val subobjectCalls = reading.subobjectCalls.toMutableMap()
        var built = roles.filterValues { (_, role) -> role == CONSTRUCTOR }
        while (built.isNotEmpty() && !monitor.isCancelled) {
            val found = mutableMapOf<Function, ClassDecl>()
            for ((cls, ctor) in baseConstructors(built, subobjectCalls)) {
                val taken = roles[ctor]?.first ?: found[ctor]
                when {
                    taken == null -> found[ctor] = cls
                    taken != cls -> foldedBaseConstructors.putIfAbsent(cls, ctor)
                }
            }
            roles += found.mapValues { (_, cls) -> cls to CONSTRUCTOR }
            subobjectCalls += readSubobjectCalls(found.keys, monitor)
            built = found.mapValues { (_, cls) -> cls to CONSTRUCTOR }
        }
        return roles
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

    /** The vptrs each function stores ([stores]), the functions each calls on `this`, and on what offset in it. */
    class Reading(
        val stores: Map<Function, VptrStores>,
        val thisCalls: Map<Function, Set<Function>>,
        val subobjectCalls: Map<Function, Map<Long, Set<Function>>> = emptyMap(),
    ) {
        /** The class a slot held by [held] deletes when it destroys a [cls]: [cls], or the one most derived. */
        private fun deleting(held: Set<ClassDecl>, cls: ClassDecl): ClassDecl? {
            val derived = held.filter { it == cls || it.derivesFrom(cls) }
            return derived.singleOrNull { c -> derived.all { it == c || it.derivesFrom(c) } }
        }

        /**
         * A constructor is never virtual, so a slot that stores vptrs, or calls a function that does,
         * destroys: a deleting destructor if it frees `this`, and the function it calls the destructor.
         * Where constructors return `this`, a storer that does builds. Of the rest, a storer a destructor
         * calls on `this` destroys too, a base's destructor, and every storer left builds: the decompiler
         * may not show a constructor's return (clang's at `-O0`, whose callers leave it unread).
         */
        fun roles(
            slots: Map<Function, Set<ClassDecl>>,
            convention: StructorConvention,
        ): Map<Function, Pair<ClassDecl, StructorRole>> = buildMap {
            val returnsThis = convention.constructorsReturnThis
            val owners = stores.mapNotNull { (f, s) -> storedClass(s.classes)?.let { f to it } }.toMap()
            fun mayDestroy(f: Function) = !returnsThis || stores[f]?.returnsThis != true

            for ((slot, held) in slots) {
                val own = owners[slot]
                when {
                    // Itanium's vtable holds the complete object destructor too, which frees nothing.
                    !frees(slot, convention) -> own?.let { this[slot] = it to DESTRUCTOR }

                    own != null -> deleting(held, own)?.let { this[slot] = it to DELETING_DESTRUCTOR }

                    else -> {
                        val (dtor, cls, holder) = thisCalls[slot].orEmpty().filter(::mayDestroy).mapNotNull { f ->
                            owners[f]?.let { cls -> deleting(held, cls)?.let { Triple(f, cls, it) } }
                        }.singleOrNull() ?: unstoredDestructor(slot, held, owners, convention) ?: continue
                        this[slot] = holder to DELETING_DESTRUCTOR
                        putIfAbsent(dtor, cls to DESTRUCTOR)
                    }
                }
            }
            if (returnsThis) {
                for ((f, cls) in owners) if (!mayDestroy(f)) putIfAbsent(f, cls to CONSTRUCTOR)
            }
            sortByCalls(owners)
        }

        /** Makes each storer a destructor calls on `this` a destructor too, and every other one a constructor. */
        private fun MutableMap<Function, Pair<ClassDecl, StructorRole>>.sortByCalls(owners: Map<Function, ClassDecl>) {
            var destroying = filterValues { (_, role) -> role != CONSTRUCTOR }.keys.toList()
            while (destroying.isNotEmpty()) {
                destroying = destroying.flatMap { thisCalls[it].orEmpty() }
                    .filter { it !in this && it in owners }.distinct()
                for (f in destroying) this[f] = owners.getValue(f) to DESTRUCTOR
            }
            for ((f, cls) in owners) putIfAbsent(f, cls to CONSTRUCTOR)
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
        if (writes.isEmpty() || thisStorage == null) return Reading(emptyMap(), emptyMap())
        val stores = mutableMapOf<Function, VptrStores>()
        val thisCalls = mutableMapOf<Function, Set<Function>>()
        val subobjectCalls = mutableMapOf<Function, Map<Long, Set<Function>>>()
        DecompInterface().useWith(program) { decomp ->
            for (func in writes.keys + others) {
                val high = decomp.decompiled(func, monitor) ?: continue
                writes[func]?.let { stores[func] = high.vptrStores(it) }
                subobjectCalls[func] = high.subobjectCalls()
                thisCalls[func] = subobjectCalls.getValue(func)[0L].orEmpty()
            }
        }
        return Reading(stores, thisCalls, subobjectCalls)
    }

    /** What each of [funcs] calls on a pointer into `this`, decompiled. */
    private fun readSubobjectCalls(funcs: Collection<Function>, monitor: TaskMonitor) =
        buildMap<Function, Map<Long, Set<Function>>> {
            DecompInterface().useWith(program) { decomp ->
                for (func in funcs) decomp.decompiled(func, monitor)?.let { put(func, it.subobjectCalls()) }
            }
        }

    private fun DecompInterface.decompiled(func: Function, monitor: TaskMonitor): HighFunction? {
        if (monitor.isCancelled) return null
        return decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
            ?: null.also { debug("structor-undecompiled", func.name, func.entryPoint) }
    }

    /** The functions this calls with a pointer into `this` first, by how far into it. */
    private fun HighFunction.subobjectCalls(): Map<Long, Set<Function>> = pcodeOps.asSequence()
        .filter { it.opcode == PcodeOp.CALL && it.numInputs > 1 }
        .mapNotNull { op ->
            val at = op.getInput(1).thisOffset() ?: return@mapNotNull null
            program.functionManager.getFunctionAt(op.getInput(0).address)?.let {
                at to
                    (it.getThunkedFunction(true) ?: it)
            }
        }
        .groupBy({ it.first }, { it.second }).mapValues { (_, fs) -> fs.toSet() }

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
