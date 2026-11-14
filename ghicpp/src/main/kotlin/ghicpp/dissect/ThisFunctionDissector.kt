package ghicpp.dissect

import ghicpp.ClassDecl
import ghicpp.abi.StructorConvention
import ghicpp.abi.StructorRole
import ghicpp.abi.StructorRole.CONSTRUCTOR
import ghicpp.thisStorage
import ghidra.app.decompiler.util.FillOutStructureHelper
import ghidra.program.model.address.Address
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Undefined
import ghidra.program.model.data.Undefined1DataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.*
import ghidra.program.model.scalar.Scalar
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.DiagnosticSink

/**
 * Decompiles functions for what they do with `this` ([Dissections]): the vptrs they store, the fields they store and
 * so the layout of the struct, and what they call on `this` + k. Off that, it tells [classes]' constructors and
 * destructors apart ([find]). With [fillArrays], a field one fills in a counted loop or with `memset` is read as
 * an array ([fills]).
 */
class ThisFunctionDissector(
    private val program: Program,
    classes: Collection<ClassDecl>,
    sink: DiagnosticSink,
    /** How it reads functions, and what the dissectors sharing it read already, which it doesn't decompile again. */
    private val cache: DissectionCache = DissectionCache(),
) : DiagnosticSink by sink {
    private val fillArrays get() = cache.fillArrays
    private val operatorNewNames get() = cache.operatorNewNames

    private val thisStorage = program.thisStorage()

    /** Whether a pointer points into the function's incoming `this`. */
    private val intoThis: (PointerInto) -> Boolean = { it.isThis(thisStorage) }

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
        val uses = read(slots.keys, monitor)
        val roles = uses.roles(slots, convention).toMutableMap()
        val subobjectCalls = uses.subobjectCalls.toMutableMap()
        val thisStores = uses.thisStores.toMutableMap()
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
        return FoundStructors(roles, folded, thisStores, subobjectCalls, uses.inlined)
    }

    /** What [funcs] store and call through `this`, decompiled, whatever vptrs they store. */
    fun readCalls(funcs: Collection<Function>, monitor: TaskMonitor): Dissections =
        decompile(funcs, emptyMap(), monitor)

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
     * What the functions storing the classes' vptrs store and call through `this`, decompiled. [visit] sees each
     * as decompiled, so it decompiles them all, read in [cache] already or not.
     */
    fun readStorers(monitor: TaskMonitor, visit: ((Function, HighFunction) -> Unit)? = null): Dissections =
        read(emptyList(), monitor, visit)

    /**
     * The stores of each function writing one of [tables], and what those and [others] call on `this`. A
     * store counts only through `this` at the table's own offset, which leaves out locals built inline and
     * member objects; a call, only with `this` first, which leaves out a local built and destroyed. A store into
     * what `operator new` just returned is a constructor inlined there ([inlined]).
     */
    private fun read(
        others: Collection<Function>,
        monitor: TaskMonitor,
        visit: ((Function, HighFunction) -> Unit)? = null,
    ): Dissections {
        monitor.message = "Finding vptr stores"
        val writes = program.vptrWriters(tables)
        if (writes.isEmpty()) return Dissections()
        return decompile(writes.keys + others, writes, monitor, visit = visit)
    }

    /**
     * What [funcs] store and call through `this`, decompiled, and which of [writes]' vptrs each stores; what
     * [cache] holds read the same way already isn't decompiled again, unless [visit] is to see it.
     */
    private fun decompile(
        funcs: Collection<Function>,
        writes: Map<Function, Map<Address, List<Pair<ClassDecl, Long>>>>,
        monitor: TaskMonitor,
        message: String = "Decompiling constructors and destructors",
        storedOnly: Boolean = true,
        visit: ((Function, HighFunction) -> Unit)? = null,
    ): Dissections {
        if (thisStorage == null) return Dissections()
        fun key(func: Function) = DissectionCache.Key(func, writes[func], storedOnly)
        val fill = FillOutStructureHelper(program, monitor)
        val fresh = if (visit != null) funcs else funcs.filter { key(it) !in cache.reads }
        program.decompileEach(fresh, monitor, message, {
            debug("structor-undecompiled", it.name, it.entryPoint)
        }) { func, high ->
            visit?.invoke(func, high)
            val inlined = writes[func]?.let { fill.inlined(high, it) }.orEmpty()
            val calls = high.subobjectCalls(intoThis)
            val filled = fill.fillThis(high)
            val stores = writes[func]?.let { filled.vptrStores(it, calls) }
            val fills = if (fillArrays) high.fills(intoThis).associate { it.second } else emptyMap()
            cache.reads[key(func)] = DissectionCache.Dissection(
                stores,
                calls.groupBy({ it.offset }, { it.callee }).mapValues { (_, fs) -> fs.toSet() },
                filled.thisStores(storedOnly).withFills(fills),
                inlined,
            )
        }
        return Dissections(funcs.mapNotNull { f -> cache.reads[key(f)]?.let { f to it } }.toMap())
    }

    /**
     * The constructors [high] inlines after a call of `operator new` with a constant size: what the call returns
     * followed as `this` is, through copies, casts and offsets, and which of [at]'s vptrs go at its start. Each
     * class's part runs from its first store to the next class's, the first's from the call, and the last's to
     * the end of the function. None where the allocation takes no vptr of these classes.
     */
    private fun FillOutStructureHelper.inlined(
        high: HighFunction,
        at: Map<Address, List<Pair<ClassDecl, Long>>>,
    ): List<InlinedConstruction> = high.pcodeOps.asSequence().filter { it.isOperatorNew() }.toList().mapNotNull { new ->
        val size = new.getInput(1).takeIf { it.isConstant }?.offset?.takeIf { it > 0 } ?: return@mapNotNull null
        val fresh = new.output?.high ?: return@mapNotNull null
        processStructure(fresh, high.function, true, false, null)
        val stores = storePcodeOps.toList()
        val firsts = linkedMapOf<ClassDecl, Address>()
        for (store in stores.sortedBy { it.pcodeOp.seqnum.target }) {
            val where = store.pcodeOp.seqnum.target
            for ((cls, offset) in at[where].orEmpty()) {
                if (offset == store.offset && offset == 0L) firsts.putIfAbsent(cls, where)
            }
        }
        if (firsts.isEmpty()) return@mapNotNull null
        val starts = firsts.values.drop(1)
        fun part(where: Address) = starts.count { it <= where }
        val into: (PointerInto) -> Boolean = { it.root == fresh }
        val calls = high.subobjectCalls(into).filter { it.at > new.seqnum.target }
        val types = componentMap.iterator().asSequence().associate { (offset, dt) -> offset.toInt() to dt }
        val fields = stores.mapNotNull { store ->
            val dt = types[store.offset.toInt()]?.takeIf { it.length > 0 } ?: return@mapNotNull null
            store.pcodeOp.seqnum.target to (store.offset.toInt() to dt)
        }
        val fills = if (fillArrays) high.fills(into) else emptyList()
        val parts = firsts.keys.mapIndexed { i, cls ->
            fun <T> List<Pair<Address, T>>.own() = filter { part(it.first) == i }.map { it.second }
            InlinedPart(
                cls,
                calls.filter { part(it.at) == i }
                    .groupBy({ it.offset }, { it.callee }).mapValues { (_, fs) -> fs.toCollection(linkedSetOf()) },
                fields.own().toMap().withFills(fills.own().toMap()),
            )
        }
        InlinedConstruction(high.function, new.seqnum.target, size, parts)
            .also { debug("structor-inlined", "${it.built.name} after operator new($size)", it.at) }
    }

    private fun PcodeOp.isOperatorNew(): Boolean {
        if (opcode != PcodeOp.CALL || numInputs < 2) return false
        return program.functionManager.getFunctionAt(getInput(0).address)?.isOperatorNew() == true
    }

    private fun Function.isOperatorNew() = (getThunkedFunction(true) ?: this).name in operatorNewNames

    /**
     * The objects the callers of `operator new` build: for each call of it with a constant size, the first function
     * called after it with what it returns first, through copies, casts and offsets, at its start. That is the
     * constructor of a class with no vptr to store; or, where its constructor is inlined, a method, or another
     * function entirely, which the caller tells apart.
     */
    fun allocations(monitor: TaskMonitor): List<Allocation> {
        if (operatorNewNames.isEmpty()) return emptyList()
        val news = program.functionManager.getFunctions(true).filter { it.isOperatorNew() }
        val callers = news.flatMapTo(sortedSetOf(compareBy { it.entryPoint })) { it.getCallingFunctions(monitor) }
        val found = mutableListOf<Allocation>()
        val message = "Decompiling operator new's callers for what they build"
        program.decompileEach(callers, monitor, message) { func, high ->
            val calls = high.pcodeOps.asSequence().filter { it.opcode == PcodeOp.CALL && it.numInputs >= 2 }.toList()
            for (new in calls.filter { it.isOperatorNew() }) {
                val size = new.getInput(1).takeIf { it.isConstant }?.offset?.takeIf { it > 0 } ?: continue
                val fresh = new.output?.high ?: continue
                val first = calls.filter { it.seqnum.target > new.seqnum.target }
                    .filter { call -> call.getInput(1).pointerInto().let { it?.root == fresh && it.offset == 0L } }
                    .minByOrNull { it.seqnum.target } ?: continue
                val callee = program.functionManager.getFunctionAt(first.getInput(0).address) ?: continue
                found += Allocation(func, new.seqnum.target, size, callee.getThunkedFunction(true) ?: callee)
            }
        }
        return found
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
    private fun FillOutStructureHelper?.thisStores(storedOnly: Boolean): Stores {
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
    private fun HighFunction.fills(into: (PointerInto) -> Boolean): List<Pair<Address, Pair<Int, DataType>>> =
        pcodeOps.asSequence().mapNotNull { op ->
            when (op.opcode) {
                PcodeOp.STORE -> loopFill(op, into)
                PcodeOp.CALL -> memsetFill(op, into)
                else -> null
            }?.let { op.seqnum.target to it }
        }.toList()

    /** The array the loop [store] stores in fills, where its pointer steps from `this` + k by what it stores. */
    private fun loopFill(store: PcodeOp, into: (PointerInto) -> Boolean): Pair<Int, DataType>? {
        val size = store.getInput(2).size
        val phi = store.getInput(1).uncopied().def?.takeIf { it.opcode == PcodeOp.MULTIEQUAL } ?: return null
        val inputs = phi.inputs.map { it.uncopied() }
        val start = inputs.firstNotNullOfOrNull { it.offsetInto(into) } ?: return null
        if (inputs.none { it.steps(phi.output, size.toLong()) }) return null
        val count = phi.parent.countdown() ?: return null
        val elem = Undefined.getUndefinedDataType(size)
        return start.toInt() to ArrayDataType(elem, count, size, program.dataTypeManager)
    }

    /** `memset(this + k, c, n)`'s n bytes at k, where `memset` is named so and n is a constant. */
    private fun memsetFill(call: PcodeOp, into: (PointerInto) -> Boolean): Pair<Int, DataType>? {
        if (call.numInputs < 4) return null
        val callee = program.functionManager.getFunctionAt(call.getInput(0).address) ?: return null
        if ((callee.getThunkedFunction(true) ?: callee).name !in MEMSET_NAMES) return null
        val at = call.getInput(1).uncopied().offsetInto(into) ?: return null
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

    /** The calls this makes with a pointer into `this`, or what else [into] says, first. */
    private fun HighFunction.subobjectCalls(into: (PointerInto) -> Boolean): List<SubobjectCall> =
        pcodeOps.asSequence().mapNotNull { op ->
            if (op.opcode != PcodeOp.CALL || op.numInputs < 2) return@mapNotNull null
            val offset = op.getInput(1).offsetInto(into) ?: return@mapNotNull null
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

    /** How far past what [into] says, `this` say, [this] points; null if it points into something else. */
    private fun Varnode.offsetInto(into: (PointerInto) -> Boolean) = pointerInto()?.takeIf(into)?.offset

    private companion object {
        val MEMSET_NAMES = setOf("memset", "_memset")

        /** The most elements a fill may count, past which its count is likely no constant at all. */
        const val MAX_FILL = 0x10000

        const val MAX_COPIES = 8
    }
}

/** A call of `operator new([size])` at [at] in [caller], and the first function [caller] calls on what it returns. */
class Allocation(val caller: Function, val at: Address, val size: Long, val firstCalled: Function)

/**
 * How [ThisFunctionDissector]s read functions: with [fillArrays], a field one fills in a counted loop or with
 * `memset` is an array; after a call of one of [operatorNewNames], `operator new(size)`, a constructor inlined
 * builds its object. And what the dissectors sharing it read of each function already, so that a parser that
 * dissects as it parses ([DissectingParser]) and the class pass after it decompile each function once.
 */
class DissectionCache(
    val fillArrays: Boolean = true,
    /** None by default: only a dissector given vptrs to look for reads a constructor inlined after one. */
    val operatorNewNames: Set<String> = emptySet(),
) {
    /** A function, read for these vptrs, for what it stores only or loads too. */
    internal data class Key(
        val func: Function,
        val writes: Map<Address, List<Pair<ClassDecl, Long>>>?,
        val storedOnly: Boolean,
    )

    /** One function's share of [Dissections]. */
    internal class Dissection(
        val stores: VptrStores? = null,
        val subobjectCalls: Map<Long, Set<Function>> = emptyMap(),
        val thisStores: Stores = emptyMap(),
        val inlined: List<InlinedConstruction> = emptyList(),
    )

    internal val reads = mutableMapOf<Key, Dissection>()
}

internal fun DissectionCache.Dissection?.orEmpty() = DissectionCache.Dissection()

/**
 * A parser that dissects the vptr storers as it parses: in the [cache] the class pass gives it before it
 * parses, which reads them as the class pass does and so spares it decompiling them again.
 */
interface DissectingParser {
    var cache: DissectionCache
}
