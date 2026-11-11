package ghicpp.recover

import ghicpp.*
import ghicpp.ClassDecl
import ghicpp.abi.StructorConvention
import ghicpp.abi.StructorRole
import ghicpp.abi.StructorRole.*
import ghicpp.introducingClass
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.util.FillOutStructureHelper
import ghidra.program.model.address.Address
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.NoisyStructureBuilder
import ghidra.program.model.data.Undefined
import ghidra.program.model.data.Undefined1DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeBlockBasic
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.scalar.Scalar
import ghidra.util.task.TaskMonitor
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

/**
 * What [StructorFinder.find] found: each structor's class and role ([roles]), each constructor a linker folded
 * into another class's that builds [folded] classes too, and the fields each function read stores through
 * `this`.
 */
class FoundStructors(
    val roles: Map<Function, Pair<ClassDecl, StructorRole>>,
    val folded: Map<Function, Set<ClassDecl>>,
    private val thisStores: Map<Function, Map<Int, DataType>>,
) {
    /** Each constructor, by the class it builds. */
    val constructors = roles.filterValues { it.second == CONSTRUCTOR }.mapValues { it.value.first }

    /**
     * The fields each class's constructors, its own and those folded into another's, store through `this`, by
     * offset into it: its own fields where nothing else is laid, and how large it is at least. Where two
     * constructors disagree, [NoisyStructureBuilder] keeps the more specific type, as it does for one.
     */
    val constructorStores: Map<ClassDecl, Map<Int, DataType>> by lazy {
        val built = constructors.map { (f, cls) -> f to cls } + folded.flatMap { (f, cs) -> cs.map { f to it } }
        built.groupBy({
            it.second
        }, { it.first }).mapValues { (_, fs) -> mergedStores(fs.map { thisStores[it].orEmpty() }) }
    }
}

/** [stores] by offset, merged in a [NoisyStructureBuilder], which keeps the more specific type where two disagree. */
internal fun mergedStores(stores: Iterable<Map<Int, DataType>>): Map<Int, DataType> {
    val fields = NoisyStructureBuilder()
    for (store in stores) store.forEach { (at, dt) -> fields.addDataType(at.toLong(), dt) }
    return fields.iterator().asSequence().associate { (at, dt) -> at.toInt() to dt }
}

/**
 * Finds constructors and destructors among [classes]' by the vtables they store into `this`, decompiled. With
 * [fillArrays], a field one fills in a counted loop or with `memset` is read as an array ([thisFills]).
 */
class StructorFinder(
    private val program: Program,
    classes: Collection<ClassDecl>,
    sink: DiagnosticSink,
    private val fillArrays: Boolean = true,
) : DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    private val tables = classes.vptrTables(program)

    /**
     * Each structor's class and role, given [slots]: each vtable slot's function, and the classes holding it.
     * A base with no vtable to store is built by the one function each of its deriving class's constructors
     * calls on its subobject ([baseConstructors]).
     */
    fun find(
        slots: Map<Function, Set<ClassDecl>>,
        convention: StructorConvention,
        monitor: TaskMonitor,
    ): FoundStructors {
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
            val more = decompile(found.keys, emptyMap(), monitor, "Decompiling base constructors")
            subobjectCalls += more.subobjectCalls
            thisStores += more.thisStores
            built = found.mapValues { (_, cls) -> cls to CONSTRUCTOR }
        }
        return FoundStructors(roles, folded, thisStores)
    }

    /** The fields each of [funcs] loads or stores through `this`, decompiled, by offset into it, typed off how. */
    fun thisFields(funcs: Collection<Function>, monitor: TaskMonitor) =
        decompile(funcs, emptyMap(), monitor, "Decompiling methods for their fields", storedOnly = false).thisStores

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
     * offset into it ([subobjectCalls]), and the fields each stores through `this`, by offset ([thisStores]).
     */
    class Reading(
        val stores: Map<Function, VptrStores>,
        val subobjectCalls: Map<Function, Map<Long, Set<Function>>>,
        val thisStores: Map<Function, Map<Int, DataType>> = emptyMap(),
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
         * `this`, destroying the class that introduced the slot ([introducingClass]).
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
            else -> introducingClass(held)?.let { Triple(dtor, it, it) }
        }

        private fun frees(f: Function, convention: StructorConvention) =
            thisCalls[f].orEmpty().any { it.name in convention.operatorDeleteNames }
    }

    /** What the functions storing the classes' vptrs store and call through `this`, decompiled. */
    fun readStorers(monitor: TaskMonitor): Reading = read(emptyList(), monitor)

    /**
     * The stores of each function writing one of [tables], and what those and [others] call on `this`. A
     * store counts only through `this` at the table's own offset, which leaves out locals built inline and
     * member objects; a call, only with `this` first, which leaves out a local built and destroyed.
     */
    private fun read(others: Collection<Function>, monitor: TaskMonitor): Reading {
        monitor.setMessage("Finding vptr stores")
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
        message: String = "Decompiling constructors and destructors",
        storedOnly: Boolean = true,
    ): Reading {
        val stores = mutableMapOf<Function, VptrStores>()
        val subobjectCalls = mutableMapOf<Function, Map<Long, Set<Function>>>()
        val thisStores = mutableMapOf<Function, Map<Int, DataType>>()
        if (thisStorage != null) {
            val fill = FillOutStructureHelper(program, monitor)
            monitor.initialize(funcs.size.toLong(), message)
            DecompInterface().useWith(program) { decomp ->
                for (func in funcs) {
                    monitor.incrementProgress()
                    val high = decomp.decompiled(func, monitor) ?: continue
                    val calls = high.subobjectCalls()
                    val filled = fill.fillThis(high)
                    writes[func]?.let { stores[func] = filled.vptrStores(it, calls) }
                    subobjectCalls[func] =
                        calls.groupBy({ it.offset }, { it.callee }).mapValues { (_, fs) -> fs.toSet() }
                    val fills = if (fillArrays) high.thisFills() else emptyMap()
                    thisStores[func] = filled.thisStores(storedOnly).withFills(fills)
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

    /**
     * Follows `this` through [high] as Ghidra's Auto Fill in Structure does, through copies, casts and offsets,
     * for [thisStores] and [vptrStores] to read; null where `this` goes unread.
     */
    private fun FillOutStructureHelper.fillThis(high: HighFunction): FillOutStructureHelper? {
        val thisVar = high.thisVariable() ?: return null
        processStructure(thisVar, high.function, true, false, null)
        return this
    }

    /**
     * The fields the function filled stores through `this`, or [storedOnly] false loads too, by offset into it,
     * typed off what it stores or loads.
     */
    private fun FillOutStructureHelper?.thisStores(storedOnly: Boolean): Map<Int, DataType> {
        if (this == null) return emptyMap()
        val stored = storePcodeOps.mapTo(mutableSetOf()) { it.offset }
        return componentMap.iterator().asSequence()
            .filter { (at, dt) -> (!storedOnly || at in stored) && dt.length > 0 }
            .associate { (at, dt) -> at.toInt() to dt }
    }

    /**
     * The arrays [this] fills through `this`, by offset into it: a pointer from `this` + k stepping by what it
     * stores each turn of a loop that a counter counts down from a constant, as x86's `rep stos` does, or a
     * call of `memset` with a constant size.
     */
    private fun HighFunction.thisFills(): Map<Int, DataType> = buildMap {
        for (op in pcodeOps.asSequence()) {
            when (op.opcode) {
                PcodeOp.STORE -> loopFill(op)?.let { (at, dt) -> put(at, dt) }
                PcodeOp.CALL -> memsetFill(op)?.let { (at, dt) -> put(at, dt) }
            }
        }
    }

    /** The array the loop [store] stores in fills, where its pointer steps from `this` + k by what it stores. */
    private fun loopFill(store: PcodeOp): Pair<Int, DataType>? {
        val size = store.getInput(2).size
        val phi = store.getInput(1).uncopied().def?.takeIf { it.opcode == PcodeOp.MULTIEQUAL } ?: return null
        val inputs = phi.inputs.map { it.uncopied() }
        val start = inputs.firstNotNullOfOrNull { it.thisOffset() } ?: return null
        if (inputs.none { it.steps(phi.output, size.toLong()) }) return null
        val count = phi.parent.countdown() ?: return null
        val elem = Undefined.getUndefinedDataType(size)
        return start.toInt() to ArrayDataType(elem, count, size, program.dataTypeManager)
    }

    /** `memset(this + k, c, n)`'s n bytes at k, where `memset` is named so and n is a constant. */
    private fun memsetFill(call: PcodeOp): Pair<Int, DataType>? {
        if (call.numInputs < 4) return null
        val callee = program.functionManager.getFunctionAt(call.getInput(0).address) ?: return null
        if ((callee.getThunkedFunction(true) ?: callee).name !in MEMSET_NAMES) return null
        val at = call.getInput(1).uncopied().thisOffset() ?: return null
        val n = call.getInput(3).uncopied().takeIf { it.isConstant }?.offset?.toInt()?.takeIf { it in 1..MAX_FILL }
            ?: return null
        return at.toInt() to ArrayDataType(Undefined1DataType.dataType, n, 1, program.dataTypeManager)
    }

    /** Whether [this] is [from] stepped by [by] bytes, `from + by` or `from[1]` of [by]-byte elements. */
    private fun Varnode.steps(from: Varnode, by: Long): Boolean {
        val op = def ?: return false
        fun const(i: Int, value: Long) = op.getInput(i).let { it.isConstant && it.offset == value }
        return op.getInput(0) == from && when (op.opcode) {
            PcodeOp.PTRADD -> const(1, 1L) && const(2, by)
            PcodeOp.INT_ADD -> const(1, by)
            else -> false
        }
    }

    /** How many turns the loop heading at [this] takes: the constant one counter there counts down from by 1. */
    private fun PcodeBlockBasic.countdown(): Int? = iterator.asSequence()
        .filter { it.opcode == PcodeOp.MULTIEQUAL }
        .mapNotNull { phi ->
            val inputs = phi.inputs.map { it.uncopied() }
            val decrements = inputs.any { v ->
                val op = v.def
                op != null && op.opcode == PcodeOp.INT_ADD && op.getInput(0) == phi.output &&
                    op.getInput(1).let {
                        it.isConstant && Scalar(it.size * Byte.SIZE_BITS, it.offset).signedValue == -1L
                    }
            }
            inputs.singleOrNull { it.isConstant }?.offset?.toInt()?.takeIf { decrements && it in 1..MAX_FILL }
        }
        .singleOrNull()

    /** [this] through the copies the decompiler leaves where it merges a loop's variables. */
    private fun Varnode.uncopied(): Varnode {
        var v = this
        repeat(MAX_COPIES) { v = v.def?.takeIf { it.opcode == PcodeOp.COPY }?.getInput(0) ?: return v }
        return v
    }

    /** The variable `this` comes in as, at [thisStorage]; null where nothing reads it. */
    private fun HighFunction.thisVariable(): HighVariable? = pcodeOps.asSequence()
        .flatMap { it.inputs.asSequence() }
        .firstOrNull { it.isInput && it.address == thisStorage }?.high

    /** A call at [at] of [callee] with a pointer [offset] bytes into `this` first. */
    private class SubobjectCall(val at: Address, val offset: Long, val callee: Function)

    /** The calls this makes with a pointer into `this` first. */
    private fun HighFunction.subobjectCalls(): List<SubobjectCall> = pcodeOps.asSequence().mapNotNull { op ->
        if (op.opcode != PcodeOp.CALL || op.numInputs < 2) return@mapNotNull null
        val offset = op.getInput(1).thisOffset() ?: return@mapNotNull null
        val callee = program.functionManager.getFunctionAt(op.getInput(0).address) ?: return@mapNotNull null
        SubobjectCall(op.seqnum.target, offset, callee.getThunkedFunction(true) ?: callee)
    }.toList()

    /**
     * Which of the vptrs [at] holds the function filled stores through `this`, at the offset each belongs at,
     * and which of its [calls] come before the first of those stores and after the last, by address.
     */
    private fun FillOutStructureHelper?.vptrStores(
        at: Map<Address, List<Pair<ClassDecl, Long>>>,
        calls: List<SubobjectCall>,
    ): VptrStores {
        val hits = this?.storePcodeOps.orEmpty().mapNotNull { store ->
            val where = store.pcodeOp.seqnum.target
            val hit = at[where].orEmpty().filter { it.second == store.offset }.map { it.first }
            hit.takeIf { it.isNotEmpty() }?.let { where to it }
        }
        val classes = hits.flatMapTo(mutableSetOf()) { it.second }
        val first = hits.minOfOrNull { it.first } ?: return VptrStores(classes)
        val last = hits.maxOf { it.first }
        return VptrStores(
            classes,
            before = calls.filter { it.at < first }.mapTo(mutableSetOf()) { it.callee },
            after = calls.filter { it.at > last }.mapTo(mutableSetOf()) { it.callee },
        )
    }

    /** How far past `this` [this] points; null if it points into something else. */
    private fun Varnode.thisOffset() = pointerInto()?.takeIf { it.isThis(thisStorage) }?.offset

    private companion object {
        val MEMSET_NAMES = setOf("memset", "_memset")

        /** The most elements a fill may count, past which its count is likely no constant at all. */
        const val MAX_FILL = 0x10000

        const val MAX_COPIES = 8
    }
}

/** [this] with the arrays [fills] in place of what it stores where they lie, but at each one's start. */
private fun Map<Int, DataType>.withFills(fills: Map<Int, DataType>): Map<Int, DataType> {
    if (fills.isEmpty()) return this
    val covered = filterKeys { at -> fills.none { (start, dt) -> at in start until start + dt.length } }
    return covered + fills
}
