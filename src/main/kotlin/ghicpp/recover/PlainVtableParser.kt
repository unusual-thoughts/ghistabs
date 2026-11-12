package ghicpp.recover

import ghicpp.*
import ghicpp.abi.*
import ghicpp.abi.msvc.Msvc
import ghicpp.dissect.DissectingParser
import ghicpp.dissect.DissectionCache
import ghicpp.dissect.Dissections
import ghicpp.dissect.ThisFunctionDissector
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import ghidrakt.components
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.diagnose.DummySink
import ghidrakt.minus

/** A class known by its vftables alone, with no RTTI to give it bases: those its structors show ([inferBases]). */
class PlainClass(override val ns: Namespace, override val vftables: List<VtableRecord>) : ClassDecl {
    override val name: String get() = ns.name
    override val bases = mutableListOf<ClassBase>()
}

/** The candidate bases of each class, as [inferBases] finds them, off their tables' [slots]. */
internal class BaseCandidates(private val slots: Map<out ClassDecl, List<Function?>>) {
    val byClass = mutableMapOf<ClassDecl, MutableSet<ClassDecl>>()

    private fun length(c: ClassDecl) = slots[c]?.size ?: 0

    private fun add(derived: ClassDecl, base: ClassDecl) {
        if (derived != base) byClass.getOrPut(derived) { mutableSetOf() } += base
    }

    /** Off the calls of each structor on `this`, and the vptrs it stores together. */
    fun addStructors(uses: Dissections) {
        for ((f, stores) in uses.stores) {
            val own = stores.classes
            val callees = uses.subobjectCalls[f].orEmpty()[0L].orEmpty()
            for (base in callees.flatMap { uses.stores[it]?.classes.orEmpty() }.filterNot { it in own }) {
                own.forEach { add(it, base) }
            }
            val inlined = own.groupBy(::length).toSortedMap().values
            if (inlined.all { it.size == 1 }) inlined.zipWithNext { (base), (derived) -> add(derived, base) }
        }
        for (built in uses.inlined) {
            // After `operator new` it can only be building, so each vptr stored is a base of the next.
            built.order.zipWithNext { base, derived -> add(derived, base) }
            for (part in built.parts) {
                val callees = part.calls[0L].orEmpty()
                for (base in callees.flatMap { uses.stores[it]?.classes.orEmpty() }.filterNot { it in built.order }) {
                    add(part.cls, base)
                }
            }
        }
    }

    /** Off the functions several tables hold in one slot, each introduced by the shortest. */
    fun addSharedSlots() {
        val held = slots.flatMap { (c, fs) -> fs.mapIndexedNotNull { i, f -> f?.let { Triple(it, i, c) } } }
        val holders = held.groupBy({ it.first to it.second }, { it.third })
        for ((_, at) in held.groupBy { it.first }) {
            if (at.map { it.second }.distinct().size != 1) continue
            val classes = at.map { it.third }.distinct()
            val shortest = classes.minOf(::length)
            val introducer = classes.singleOrNull { length(it) == shortest } ?: continue
            for (cls in classes) {
                if (cls != introducer && !cls.inheritsPast(introducer, slots, holders, ::length)) add(cls, introducer)
            }
        }
    }

    /**
     * The direct bases of [classes] at the start of their objects, off what their structors store and call
     * ([uses]) and the functions their tables' [slots] share, each table's slots in order, null where no function
     * of the program's own is (a null slot, a pure virtual stub, an import) or one that never returns, as an unnamed
     * pure virtual stub doesn't.
     *
     * A function storing D's vptr that calls on `this` a function storing B's makes B a base of D, as a constructor
     * builds its bases and a destructor destroys them. A function storing several classes' vptrs at once, inlining
     * its bases', stores a base's first in a constructor and last in a destructor, so there their tables' lengths
     * order them: a derived class's table holds at least its base's slots. A constructor inlined after `operator
     * new` can only build, so there the order of its stores says.
     *
     * A function several tables hold, in the same slot of each, was introduced by a class all of theirs derive from:
     * the one with the shortest table, if no other is as short, which is then a candidate base of the others. Not
     * where that class overrides a slot that the other inherits from a class with a shorter table still, which a class
     * deriving from it couldn't ([inheritsPast]); and not for a function in different slots, as the linker folds
     * functions alike across unrelated classes.
     *
     * Of the candidates, the one deriving from all the others is the base; none if no one does, or if two classes
     * would derive from each other. A call on `this` + k is no evidence: it builds a member as well as a base, and
     * only a store of D's own table at k, which [PlainVtables] doesn't place, would tell them apart.
     */
    fun inferBases(classes: Collection<PlainClass>, uses: Dissections) {
        addStructors(uses)
        addSharedSlots()
        val direct = byClass.mapValues { (_, cs) -> cs.mostDerived(byClass) }
        for (cls in classes) {
            val base = direct[cls] ?: continue
            if (direct[base] != cls) cls.bases += ClassBase(base, isVirtual = false, Access.PUBLIC, 0L)
        }
    }
}

/**
 * Whether this class holds, in a slot [base] overrides, a function that a class with a shorter table than
 * this one's holds there too: inherited from past [base], so not through it.
 */
private fun ClassDecl.inheritsPast(
    base: ClassDecl,
    slots: Map<out ClassDecl, List<Function?>>,
    holders: Map<Pair<Function, Int>, List<ClassDecl>>,
    length: (ClassDecl) -> Int,
): Boolean {
    val own = slots[this].orEmpty()
    return slots[base].orEmpty().withIndex().any { (i, b) ->
        val d = own.getOrNull(i)
        b != null && d != null && b != d &&
            holders[d to i].orEmpty().any { it != this && length(it) < length(this) }
    }
}

/** The one of these that every other is a candidate base of, directly or not. */
private fun Set<ClassDecl>.mostDerived(candidates: Map<ClassDecl, Set<ClassDecl>>): ClassDecl? {
    fun reaches(from: ClassDecl, to: ClassDecl): Boolean {
        val seen = mutableSetOf(from)
        val todo = ArrayDeque(listOf(from))
        while (todo.isNotEmpty()) {
            for (b in candidates[todo.removeFirst()].orEmpty()) {
                if (b == to) return true
                if (seen.add(b)) todo += b
            }
        }
        return false
    }
    return singleOrNull { c -> all { it == c || reaches(c, it) } }
}

/**
 * The classes whose `vftable` labels no ABI's records describe, as [GenericVftableFinder] seeds them or a user
 * labels them, for the class pass: each label in a class namespace with no RTTI labels of its own, which isn't
 * an ABI's vtable symbol nor the stabs import's, read as [PlainVtables]. A class with RTTI goes to its ABI's
 * parser, which knows its bases; these get theirs off their structors ([BaseCandidates.inferBases]).
 */
class PlainVtableParser(private val program: Program, private val sink: DiagnosticSink = DummySink) :
    RttiParser,
    DissectingParser {
    /** How it reads the storers: a constructor inlined after `operator new` orders the bases it builds, if read. */
    override var cache = DissectionCache()

    override val abi get() = PlainVtables

    private val symbols = program.symbolTable
    private val ptr = program.defaultPointerSize.toLong()

    override fun parse(monitor: TaskMonitor): ClassPassInput {
        monitor.message = "Reading vftable labels"
        val classes = symbols.getSymbols(ClassNaming.VFTABLE).iterator().asSequence()
            .filter { it.isPlain() }
            .groupBy { it.parentNamespace.id }
            .values.map { labels ->
                PlainClass(labels.first().parentNamespace, labels.map { PlainVtables.recordAt(program, it.address) })
            }
        val uses = ThisFunctionDissector(program, classes, sink, cache).readStorers(monitor)
        val slots = classes.associateWith { c ->
            c.vftables.firstOrNull()?.let { slotsOf(it, keepNulls = true) }.orEmpty().map { at ->
                // An unnamed pure virtual stub never returns: it aborts.
                at.takeIf { it.offset != 0L }?.let { program.slotFunction(it, PlainVtables) }
                    ?.takeUnless { it.hasNoReturn() }
            }
        }
        monitor.message = "Inferring bases from constructors"
        BaseCandidates(slots).inferBases(classes, uses)
        return ClassPassInput(classes, classes, holders(classes))
    }

    /** Whether [this] labels a table no ABI's records describe, in a class that has none. */
    private fun Symbol.isPlain(): Boolean {
        if (source == SourceType.IMPORTED || parentNamespace !is GhidraClass) return false
        if (symbols.getSymbols(address).any { CxxAbi.ofVtableSymbol(it.name) != null }) return false
        val meta = runCatching { symbols.getSymbols(address - ptr) }.getOrNull().orEmpty()
        return meta.none { it.name == Msvc.VFTABLE_META_PTR } &&
            symbols.getSymbols(parentNamespace).iterator().asSequence().none { it.name in RTTI_LABELS }
    }

    /** Each function a slot holds, and the classes whose tables hold it. */
    private fun holders(classes: List<PlainClass>) = buildMap {
        for (cls in classes) {
            for (record in cls.vftables) {
                for (slot in slotsOf(record)) {
                    val func = program.slotFunction(slot, PlainVtables) ?: continue
                    getOrPut(func) { mutableSetOf() } += cls
                }
            }
        }
    } as Map<Function, Set<ClassDecl>>

    /**
     * The functions [record]'s slots point at, without its null slots unless [keepNulls]: those of the struct laid
     * at it, which ends where its table does, else as many as the words that follow hold ([VtableRecord.slots]),
     * which may run into the next table.
     */
    private fun slotsOf(record: VtableRecord, keepNulls: Boolean = false): List<Address> {
        val laid = program.listing.getDataAt(record.addressPoint)
        if (laid == null || laid.numComponents == 0 || !laid.isStructure) return record.slots(program)
        return laid.components.mapNotNull { it.value as? Address }.filter { keepNulls || it.offset != 0L }
    }

    private companion object {
        /** The labels the RTTI of a class with any is laid under: Itanium's typeinfo and vtable, MSVC's records. */
        val RTTI_LABELS = setOf(
            ClassNaming.TYPEINFO,
            ClassNaming.VTABLE,
            Msvc.TYPE_DESCRIPTOR,
            Msvc.COMPLETE_OBJECT_LOCATOR,
            Msvc.CLASS_HIERARCHY_DESCRIPTOR,
        )
    }
}
