package ghicpp.recover

import ghicpp.Access
import ghicpp.ClassBase
import ghicpp.ClassDecl
import ghicpp.ClassNaming
import ghicpp.ClassPassInput
import ghicpp.abi.CxxAbi
import ghicpp.abi.PlainVtables
import ghicpp.abi.RttiParser
import ghicpp.abi.VtableRecord
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.slotFunction
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink

/** A class known by its vftables alone, with no RTTI to give it bases: those its structors show ([inferBases]). */
class PlainClass(override val ns: Namespace, override val vftables: List<VtableRecord>) : ClassDecl {
    override val name: String get() = ns.name
    override val bases = mutableListOf<ClassBase>()
}

/**
 * The direct bases of [classes] at the start of their objects, off what their structors store and call
 * ([reading]): a function storing D's vptr that calls on `this` a function storing B's makes B a base of D, as a
 * constructor builds its bases and a destructor destroys them. A function storing several classes' vptrs at once,
 * inlining its bases', stores a base's first in a constructor and last in a destructor, so there [slotCounts]
 * order them: a derived class's table holds at least its base's slots. Of the candidates, the one deriving from all
 * the others is the base; none if no one does, or if two classes would derive from each other.
 *
 * A call on `this` + k is no evidence: it builds a member as well as a base, and only a store of D's own table at
 * k, which [PlainVtables] doesn't place, would tell them apart.
 */
fun inferBases(classes: Collection<PlainClass>, reading: StructorFinder.Reading, slotCounts: Map<out ClassDecl, Int>) {
    val candidates = mutableMapOf<ClassDecl, MutableSet<ClassDecl>>()
    fun candidate(derived: ClassDecl, base: ClassDecl) {
        if (derived != base) candidates.getOrPut(derived) { mutableSetOf() } += base
    }
    for ((f, stores) in reading.stores) {
        val own = stores.classes
        val callees = reading.subobjectCalls[f].orEmpty()[0L].orEmpty()
        for (base in callees.flatMap { reading.stores[it]?.classes.orEmpty() }.filterNot { it in own }) {
            own.forEach { candidate(it, base) }
        }
        val inlined = own.groupBy { slotCounts[it] ?: 0 }.toSortedMap().values
        if (inlined.all { it.size == 1 }) inlined.zipWithNext { (base), (derived) -> candidate(derived, base) }
    }
    val direct = candidates.mapValues { (_, cs) -> cs.mostDerived(candidates) }
    for (cls in classes) {
        val base = direct[cls] ?: continue
        if (direct[base] != cls) cls.bases += ClassBase(base, isVirtual = false, Access.PUBLIC, 0L)
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
 * parser, which knows its bases; these get theirs off their structors ([inferBases]).
 */
class PlainVtableParser(private val program: Program, private val sink: DiagnosticSink = DummySink) : RttiParser {
    override val abi get() = PlainVtables

    private val symbols = program.symbolTable

    override fun parse(monitor: TaskMonitor): ClassPassInput {
        val classes = symbols.getSymbols(ClassNaming.VFTABLE).iterator().asSequence()
            .filter { it.isPlain() }
            .groupBy { it.parentNamespace.id }
            .values.map { labels ->
                PlainClass(labels.first().parentNamespace, labels.map { PlainVtables.recordAt(program, it.address) })
            }
        val reading = StructorFinder(program, classes, sink).readStorers(monitor)
        val slotCounts = classes.associateWith { c -> c.vftables.firstOrNull()?.let { slotsOf(it).size } ?: 0 }
        inferBases(classes, reading, slotCounts)
        return ClassPassInput(classes, classes, holders(classes))
    }

    /** Whether [this] labels a table no ABI's records describe, in a class that has none. */
    private fun Symbol.isPlain(): Boolean {
        if (source == SourceType.IMPORTED || parentNamespace !is GhidraClass) return false
        if (symbols.getSymbols(address).any { CxxAbi.ofVtableSymbol(it.name) != null }) return false
        val meta = runCatching { address.subtract(program.defaultPointerSize.toLong()) }.getOrNull()
        if (meta != null && symbols.getSymbols(meta).any { it.name == Msvc.VFTABLE_META_PTR }) return false
        return symbols.getSymbols(parentNamespace).iterator().asSequence().none { it.name in RTTI_LABELS }
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
     * The functions [record]'s slots point at: those of the struct laid at it, which ends where its table
     * does, else as many as the words that follow hold ([VtableRecord.slots]), which may run into the next table.
     */
    private fun slotsOf(record: VtableRecord): List<Address> {
        val laid = program.listing.getDataAt(record.addressPoint)
        if (laid == null || laid.numComponents == 0 || !laid.isStructure) return record.slots(program)
        return (0 until laid.numComponents).mapNotNull { laid.getComponent(it).value as? Address }
            .filter { it.offset != 0L }
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
