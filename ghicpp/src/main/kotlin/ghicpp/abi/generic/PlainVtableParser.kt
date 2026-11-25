package ghicpp.abi.generic

import ghicpp.*
import ghicpp.abi.functionSlots
import ghicpp.abi.holdsPureVirtualStub
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.ofVtableSymbol
import ghicpp.abi.slotFunction
import ghicpp.abi.slots
import ghicpp.dissect.*
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.diagnose.DummySink
import ghidrakt.diagnose.Level

/**
 * The class in [stored] with the longest primary table, or null on a tie. A class's table holds all of its bases'
 * slots, so the longest one belongs to the most derived class.
 */
internal fun Program.longestPrimary(stored: Collection<ClassDecl>): PlainClass? = stored.filterIsInstance<PlainClass>()
    .groupBy { it.vftables.firstOrNull()?.slots(this)?.size ?: 0 }.maxByOrNull { it.key }?.value?.singleOrNull()

/**
 * A class known by its vftables alone, with no RTTI to give it bases: those its structors show ([inferBases]). Its
 * [virtualBases] are its direct virtual ones, each where the secondary table its subobject has sits.
 */
class PlainClass(override val ns: Namespace, override val vftables: List<VtableRecord>) : ClassDecl {
    override val name: String get() = ns.name
    override val bases = mutableListOf<ClassBase>()
    override val virtualBases get() = bases.filter { it.isVirtual }.map { it.copy(offsetSource = SourceType.ANALYSIS) }

    /** The vbase offsets in front of its primary's `offset_to_top`, where it has an Itanium header. */
    var headerVbaseOffsets: Set<Long> = emptySet()

    override val vbaseOffsets get() = super.vbaseOffsets + headerVbaseOffsets
}

/**
 * The candidate bases of each class, as [inferBases] finds them, off their tables' [slots], and which of those are
 * [pure] virtual, by index. It tells [sink] what it takes each base off, and the evidence it can't use: tables or
 * stores tied, candidates no one of which derives from the others.
 */
internal class BaseCandidates(
    private val slots: Map<out ClassDecl, List<Function?>>,
    private val pure: Map<out ClassDecl, Set<Int>> = emptyMap(),
    sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    val byClass = mutableMapOf<ClassDecl, MutableSet<ClassDecl>>()

    /** What each candidate base was taken off, by derived class and base. */
    private val evidence = mutableMapOf<Pair<ClassDecl, ClassDecl>, MutableSet<String>>()

    private fun length(c: ClassDecl) = slots[c]?.size ?: 0

    private fun add(derived: ClassDecl, base: ClassDecl, why: String) {
        if (derived == base) return
        byClass.getOrPut(derived) { mutableSetOf() } += base
        evidence.getOrPut(derived to base) { linkedSetOf() } += why
    }

    private val ClassDecl.at get() = vftables.firstOrNull()?.addressPoint

    private val Collection<ClassDecl>.names get() = joinToString(", ") { it.name }

    private fun evidenceOf(derived: ClassDecl, base: ClassDecl): String {
        val all = evidence[derived to base].orEmpty()
        val shown = all.take(MAX_EVIDENCE_SHOWN).joinToString("; ")
        return if (all.size > MAX_EVIDENCE_SHOWN) "$shown; and ${all.size - MAX_EVIDENCE_SHOWN} more" else shown
    }

    /** Off the calls of each structor on `this`, and the vptrs it stores together. */
    fun addStructors(uses: Dissections) {
        for ((f, stores) in uses.stores) {
            val own = stores.classes
            val callees = uses.subobjectCalls[f].orEmpty()[0L].orEmpty()
            for (callee in callees) {
                for (base in uses.stores[callee]?.classes.orEmpty().filterNot { it in own }) {
                    own.forEach { add(it, base, "${f.name} calls ${callee.name} on this") }
                }
            }
            val inlined = own.groupBy(::length).toSortedMap().values
            if (inlined.all { it.size == 1 }) {
                inlined.zipWithNext { (base), (derived) ->
                    add(derived, base, "${f.name} stores both, by table length")
                }
            } else {
                log(
                    "base-tie-stores",
                    "${f.name} stores all their vptrs, and their tables' lengths don't order them",
                    Level.INFO,
                    f.entryPoint,
                    degrades = own.names,
                )
            }
        }
        for (built in uses.inlined) {
            // After `operator new` it can only be building, so each vptr stored is a base of the next.
            built.order.zipWithNext { base, derived -> add(derived, base, "${built.function.name} builds both") }
            for (part in built.parts) {
                for (callee in part.calls[0L].orEmpty()) {
                    for (base in uses.stores[callee]?.classes.orEmpty().filterNot { it in built.order }) {
                        add(part.cls, base, "${built.function.name} calls ${callee.name} on what it builds")
                    }
                }
            }
        }
    }

    /**
     * Adds bases off the deleting destructors the tables hold. A deleting destructor that stores no vptr itself,
     * but calls on `this` a destructor that stores exactly one other class's vptr, destroys an object of the class
     * whose table holds it. That class's own destructor had nothing to do, so it was folded away. The class whose
     * vptr the callee stores is then a base of the class whose table holds the deleting destructor. No constructor
     * may show this: a constructor that inlines an abstract base's constructor drops the base's vptr store, since
     * the derived class's store overwrites it.
     *
     * A slot whose first argument is the object it returns ([returnsInSlot]) is skipped, as its calls build that
     * object. So is a callee not seen destroying ([destroys]). Otherwise the constructors that a virtual returning a
     * class by value calls would make every class returning one derive from it.
     */
    fun addDeletingSlots(uses: Dissections) {
        for ((cls, fs) in slots) {
            for (f in fs.filterNotNull().distinct().filterNot { it in uses.stores || it.returnsInSlot() }) {
                val callees = uses.subobjectCalls[f].orEmpty()[0L].orEmpty().filter { uses.destroys(it) }
                val destroyed = callees.flatMapTo(mutableSetOf()) { uses.stores[it]?.classes.orEmpty() }
                destroyed.singleOrNull()?.let { add(cls, it, "its table's ${f.name} destroys one") }
            }
        }
    }

    /**
     * Whether [f] is seen destroying an object. It stores a vptr, then calls on `this` itself, not on a member, a
     * function that stores another class's vptr: its base's destructor. Before its own store it calls no such
     * function, as a constructor building its bases would.
     */
    private fun Dissections.destroys(f: Function): Boolean {
        val own = stores[f]?.classes ?: return false
        fun storesOther(g: Function) = g != f && stores[g]?.classes.orEmpty().any { it !in own }
        fun List<ObjectCall>.onThis() = filter { it.offset == 0L }.callees
        return f.post().onThis().any(::storesOther) && f.pre().onThis().none(::storesOther)
    }

    /** Off the functions several tables hold in one slot, each introduced by the shortest. */
    fun addSharedSlots() {
        val held = slots.flatMap { (c, fs) -> fs.mapIndexedNotNull { i, f -> f?.let { Triple(it, i, c) } } }
        val holders = held.groupBy({ it.first to it.second }, { it.third })
        val ties = mutableMapOf<List<ClassDecl>, MutableList<String>>()
        val past = mutableMapOf<Pair<ClassDecl, ClassDecl>, MutableList<String>>()
        for ((func, at) in held.groupBy { it.first }) {
            if (at.map { it.second }.distinct().size != 1) continue
            val slot = "${func.name} in slot ${at.first().second}"
            val classes = at.map { it.third }.distinct()
            val shortest = classes.minOf(::length)
            val tied = classes.filter { length(it) == shortest }
            val introducer = tied.singleOrNull() ?: tied.singleOrNull { c -> tied.all { it == c || c.isPurerThan(it) } }
            if (introducer == null) {
                if (classes.size > 1) ties.getOrPut(tied.sortedBy { it.name }) { mutableListOf() } += slot
                continue
            }
            val how = when {
                tied.size > 1 -> "shares $slot with it, tied for the shortest table but pure"
                else -> "shares $slot"
            }
            for (cls in classes) {
                when {
                    cls == introducer -> {}

                    cls.inheritsPast(introducer, slots, holders, ::length) ->
                        past.getOrPut(cls to introducer) { mutableListOf() } += slot

                    else -> add(cls, introducer, how)
                }
            }
        }
        for ((tied, shared) in ties) {
            log(
                "base-tie-slots",
                "tie for the shortest table holding ${shared.joinToString()}, none pure where the others " +
                    "aren't: no introducer",
                Level.INFO,
                tied.first().at,
                degrades = tied.names,
            )
        }
        for ((pair, shared) in past) {
            val (cls, introducer) = pair
            log(
                "base-slot-dropped",
                "shares ${shared.joinToString()} with ${introducer.name}, but inherits a slot " +
                    "${introducer.name} overrides from further up: not taken as a direct base",
                Level.INFO,
                cls.at,
                degrades = cls.name,
            )
        }
    }

    /**
     * Whether this class's table is [pure] where [other]'s holds a function, and [other]'s nowhere this one's isn't:
     * pure where [other] overrides, as a base can be and a class deriving from one that isn't can't.
     */
    private fun ClassDecl.isPurerThan(other: ClassDecl): Boolean {
        val own = pure[this].orEmpty()
        val theirs = pure[other].orEmpty()
        return own.any { it !in theirs && slots[other].orEmpty().getOrNull(it) != null } && own.containsAll(theirs)
    }

    /**
     * The direct bases of [classes] at the start of their objects, off what their structors store and call
     * ([uses]) and the functions their tables' [slots] share, each table's slots in order, null where no function
     * of the program's own is (a null slot, a pure virtual stub, an import) or one that never returns, as an unnamed
     * pure virtual stub doesn't.
     *
     * A function storing D's vptr that calls on `this` a function storing B's makes B a base of D, as a constructor
     * builds its bases and a destructor destroys them. So does a deleting destructor in D's table that stores no
     * vptr itself ([addDeletingSlots]).
     * A function storing several classes' vptrs at once, inlining its bases', stores a base's first in a
     * constructor and last in a destructor, so there their tables' lengths order them: a derived class's table
     * holds at least its base's slots. A constructor inlined after `operator new` can only build, so there the
     * order of its stores says.
     *
     * A function several tables hold, in the same slot of each, was introduced by a class all of theirs derive from:
     * the one with the shortest table, which is then a candidate base of the others. Of several as short, the one
     * pure where each other overrides ([isPurerThan]): MSVC drops an abstract base's vptr store from the
     * constructor inlining it, as the derived class's overwrites it, so only its table tells it from them. Not
     * where that class overrides a slot that the other inherits from a class with a shorter table still, which a class
     * deriving from it couldn't ([inheritsPast]); and not for a function in different slots, as the linker folds
     * functions alike across unrelated classes.
     *
     * Of the candidates, the one deriving from all the others is the base; none if no one does, or if two classes
     * would derive from each other. A call on `this` + k is no evidence: it builds a member as well as a base, and
     * only a store of D's own table at k, which [PlainVtables] doesn't place, would tell them apart.
     */
    fun inferBases(
        classes: Collection<PlainClass>,
        uses: Dissections,
        subobjects: Map<PlainClass, Map<Long, Boolean>> = emptyMap(),
        sharing: (PlainClass, Long) -> ClassDecl? = { _, _ -> null },
    ) {
        addStructors(uses)
        addDeletingSlots(uses)
        addSharedSlots()
        val direct = byClass.mapValues { (_, cs) -> cs.mostDerived(byClass) }
        for (cls in classes) {
            val candidates = byClass[cls].orEmpty()
            val base = direct[cls]
            if (base == null) {
                if (candidates.isNotEmpty()) {
                    degradation(
                        "base-candidates-unordered",
                        cls.name,
                        "no one of its candidate bases derives from the others, so none is taken: " +
                            candidates.joinToString(" | ") { "${it.name}: ${evidenceOf(cls, it)}" },
                        cls.at,
                    )
                }
                continue
            }
            if (direct[base] == cls) {
                degradation(
                    "base-cycle",
                    cls.name,
                    "it and ${base.name} would derive from each other, so neither does: " +
                        "${evidenceOf(cls, base)} | ${evidenceOf(base, cls)}",
                    cls.at,
                )
                continue
            }
            cls.bases += ClassBase(base, isVirtual = false, access = null, 0L)
            debug("base-inferred", "${cls.name} : ${base.name}, as ${evidenceOf(cls, base)}", cls.at)
        }
        addSubobjectBases(uses, subobjects, sharing)
    }

    /**
     * Adds the bases at [subobjects]' offsets: off the structor calls on each ([subobjectBase]), else off the
     * class's table there ([sharing]).
     */
    private fun addSubobjectBases(
        uses: Dissections,
        subobjects: Map<PlainClass, Map<Long, Boolean>>,
        sharing: (PlainClass, Long) -> ClassDecl?,
    ) {
        for ((cls, offsets) in subobjects) {
            val found = offsets.mapNotNull { (offset, isVirtual) ->
                val base = subobjectBase(cls, offset, uses) ?: sharing(cls, offset)?.also {
                    debug("base-inferred-sharing", "${cls.name} : ${it.name} at +$offset, off its table there", cls.at)
                }
                base?.let { ClassBase(it, isVirtual, access = null, offset) }
            }
            // A virtual base may be one of another base's, which the complete-object constructor builds as well:
            // not while a non-virtual subobject's class is unknown, as it may be the one deriving from it.
            val unknown = offsets.count { !it.value } > found.count { !it.isVirtual }
            for (base in found.filter { it.isVirtual && unknown }) {
                degradation(
                    "base-virtual-dropped",
                    cls.name,
                    "virtual ${base.cls.name} at +${base.offset} left out, as a base subobject's class " +
                        "is unknown and may be the one deriving from it",
                    cls.at,
                )
            }
            for (base in found.filterNot { it.isVirtual && unknown }) {
                if (cls.bases.none { it.cls == base.cls }) cls.bases += base
            }
        }
        // A complete-object constructor builds every virtual base, its bases' too: one another base of the class
        // derives from is that base's, not the class's own.
        for (cls in subobjects.keys) {
            cls.bases.removeAll { b -> b.isVirtual && cls.bases.any { it !== b && it.cls.derivesFrom(b.cls) } }
        }
    }

    /**
     * The class of [cls]'s base subobject at [offset], where [cls] has a secondary table: the one class whose
     * table the functions [cls]'s structors call on `this` + [offset] store. Once [cls]'s own table is known to
     * sit there, such a call builds a base, not a member, which would have no table of [cls]'s in it.
     */
    private fun subobjectBase(cls: ClassDecl, offset: Long, uses: Dissections): ClassDecl? =
        uses.stores.filterValues { cls in it.classes }.keys
            .flatMap { f -> uses.subobjectCalls[f].orEmpty()[offset].orEmpty() }
            .flatMap { uses.stores[it]?.classes.orEmpty() }
            .filter { it != cls && !it.derivesFrom(cls) }
            .toSet()
            .let { bases -> bases.singleOrNull { b -> bases.all { it == b || b.derivesFrom(it) } } }
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

/** How many of the pieces of evidence for one base a diagnostic names. */
private const val MAX_EVIDENCE_SHOWN = 3

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
 * The classes whose `vftable` labels no ABI's records describe, as [ghicpp.recover.GenericVftableFinder] seeds
 * them or a user labels them, for the class pass: each label in a class namespace with no RTTI labels of its own,
 * which isn't an ABI's vtable symbol nor the stabs import's, read as [PlainVtables]. A class with RTTI goes to its
 * ABI's parser, which knows its bases; these get theirs off their structors ([BaseCandidates.inferBases]).
 */
class PlainVtableParser(private val program: Program, private val sink: DiagnosticSink = DummySink) :
    RttiParser,
    DissectingParser {
    /** How it reads the storers: a constructor inlined after `operator new` orders the bases it builds, if read. */
    override var cache = DissectionCache(operatorNewNames = PlainVtables.operatorNewNames)

    override val abi get() = PlainVtables

    private val symbols = program.symbolTable
    private val ptr = program.defaultPointerSize.toLong()

    override fun parse(monitor: TaskMonitor): ClassPassInput {
        monitor.message = "Reading vftable labels"
        val classes = readClasses()
        // Look up the slots' functions before reading the storers. Looking one up can create it, which changes the
        // program, and the class pass would then have to decompile the storers again.
        val targets = targetsOf(classes)
        var uses = ThisFunctionDissector(program, classes, sink, cache).readStorers(monitor)
        val vtt = program.findVttStructors(classes, uses)
        val own = targets.mapValues { (_, ats) ->
            ats.map { at -> at.takeIf { it.offset != 0L }?.let { program.slotFunction(it, PlainVtables) } }
        }
        // An unnamed pure virtual stub never returns: it aborts.
        val slots = own.mapValues { (_, fs) -> fs.map { f -> f?.takeUnless { it.hasNoReturn() } } }
        // Read the slots' functions too. addDeletingSlots needs the destructors that deleting destructors call, and
        // the class pass reads the same functions next, through the same cache.
        val held = slots.values.flatMapTo(mutableSetOf()) { it.filterNotNull() }
        val holders = holders(classes)
        uses = ThisFunctionDissector(program, classes, sink, cache).readStorers(monitor, held)
        monitor.message = "Inferring bases from constructors"
        BaseCandidates(
            slots,
            pureSlots(targets, own),
            sink,
        ).inferBases(classes, uses, classes.associateWith { subobjects(it, uses) }, sharingBase(classes))
        for (v in vtt) {
            if (v.built == v.base || v.built.bases.any { it.cls == v.base } || v.base.derivesFrom(v.built)) continue
            val isVirtual = v.offset in v.built.headerVbaseOffsets
            v.built.bases += ClassBase(v.base, isVirtual, access = null, v.offset)
        }
        return ClassPassInput(classes, classes, holders, vtt.associate { it.structor to it.base })
    }

    /**
     * What the classes read off the `vftable` labels say about the tables the finder seeded: the tables that are
     * other classes' secondary ones ([msvcSecondaries]), and the construction vtables that VTTs lead to and no
     * class holds the slots of ([findVttStructors]). The finder moves or seeds those, and the classes read again
     * then differ.
     */
    fun misplacedTables(monitor: TaskMonitor): MisplacedTables {
        val classes = readClasses()
        targetsOf(classes)
        val uses = ThisFunctionDissector(program, classes, sink, cache).readStorers(monitor)
        val unmatched = mutableSetOf<Address>()
        program.findVttStructors(classes, uses, unmatched)
        return MisplacedTables(program.msvcSecondaries(classes, uses), unmatched)
    }

    /** The slots of each class's primary table, with its null ones, its functions looked up and so created. */
    private fun targetsOf(classes: List<PlainClass>): Map<PlainClass, List<Address>> = classes.associateWith { c ->
        c.vftables.firstOrNull()?.let { slotsOf(it, keepNulls = true) }.orEmpty()
            .onEach { at -> at.takeIf { it.offset != 0L }?.let { program.slotFunction(it, PlainVtables) } }
    }

    /**
     * The class of a base subobject that no structor call names, off the secondary table of the class at that
     * offset. That table holds the base's slots in the base's order: the base's own functions where the class
     * doesn't override them, and this-adjusting thunks where it does. So the base is the class whose primary table
     * is as long and holds the same function in the most slots. Pure virtual stubs don't count, since many unrelated
     * classes hold them. It is null on a tie, or where none shares a slot.
     *
     * It is also null where a base the class is already known to have has a table at that offset. The subobject
     * then belongs to that base, so the class there is an indirect base, not a direct one.
     */
    private fun sharingBase(classes: List<PlainClass>): (PlainClass, Long) -> ClassDecl? {
        val primaries by lazy { classes.associateWith { functionSlots(it.vftables.first().addressPoint) } }
        return { cls, offset ->
            cls.vftables.drop(1).firstOrNull { it.vfptrOffset(program) == offset }
                ?.takeIf { cls.bases.none { b -> b.offset?.let { b.cls.hasTableAt(offset - it) } == true } }
                ?.let { table ->
                    val slots = functionSlots(table.addressPoint)
                    val shared = primaries
                        .filter { (other, own) -> other != cls && !other.derivesFrom(cls) && own.size == slots.size }
                        .mapValues { (_, own) -> slots.indices.count { own[it] == slots[it] && sharable(slots[it]) } }
                        .filterValues { it > 0 }
                    val most = shared.values.maxOrNull()
                    shared.filterValues { it == most }.keys.singleOrNull()
                }
        }
    }

    private fun functionSlots(at: Address) = program.functionSlots(at, PlainVtables).toList()

    private fun sharable(slot: Address) =
        slot.offset != 0L && !program.holdsPureVirtualStub(slot, PlainVtables::isPureVirtualStub)

    /**
     * Whether this class, or one of its bases at the right offset, has a table at [offset] from its start. The
     * search stops at [depth] bases deep, in case the bases inferred so far form a cycle.
     */
    private fun ClassDecl.hasTableAt(offset: Long, depth: Int = MAX_BASE_DEPTH): Boolean {
        if (offset < 0 || depth == 0) return false
        return vftables.any { it.vfptrOffset(program) == offset } ||
            bases.any { b -> b.offset?.let { b.cls.hasTableAt(offset - it, depth - 1) } == true }
    }

    /** The classes of the plain `vftable` labels: the primary first, then its secondaries by their offsets. */
    private fun readClasses(): List<PlainClass> = symbols.getSymbols(ClassNaming.VFTABLE).iterator().asSequence()
        .filter { it.isPlain() }
        .groupBy { it.parentNamespace.id }
        .values.map { labels ->
            val ns = labels.first().parentNamespace
            val secondaries = symbols.getSymbols(ns).iterator().asSequence()
                .mapNotNull { sym -> ClassNaming.plainSubobjectOffset(sym.name)?.let { it to sym } }
                .sortedBy { it.first }.map { it.second }
            PlainClass(ns, (labels + secondaries).map { PlainVtables.recordAt(program, it.address) })
        }

    /**
     * The offsets of [cls]'s base subobjects that have secondary tables, each with whether the base is virtual:
     * In an Itanium vtable group, a virtual base's offset is one of the vbase offsets in front of the primary's
     * `offset_to_top`. An MSVC class's structors store its virtual bases' tables through a vbtable.
     */
    private fun subobjects(cls: PlainClass, uses: Dissections): Map<Long, Boolean> {
        val primary = cls.vftables.firstOrNull()?.addressPoint ?: return emptyMap()
        // A construction vtable's vbase offsets place the virtual bases in the class it is built inside, not in
        // this one. Only a VTT points at a construction vtable: no code takes its address.
        val vbaseOffsets = if (primary.signedWordBefore(program, 2) == 0L && program.isTakenByCode(primary)) {
            (3..2 + MAX_VBASE_WORDS).asSequence().map { primary.signedWordBefore(program, it) }
                .takeWhile { it != null && it in ptr until PlainVtables.MAX_SUBOBJECT_OFFSET }
                .filterNotNull().toSet()
        } else {
            emptySet()
        }
        cls.headerVbaseOffsets = vbaseOffsets
        val throughVbtable = uses.stores.values.filter { cls in it.classes }
            .flatMapTo(mutableSetOf()) { ss -> ss.filter { it.throughVbtable }.map { it.offset } }
        return cls.vftables.drop(1).mapNotNull { it.vfptrOffset(program)?.takeIf { k -> k > 0 } }
            .associateWith { it in vbaseOffsets || it in throughVbtable }
    }

    /**
     * The indices of each class's primary table's pure virtual slots, off what its slots point at ([targets]) and
     * the program's own functions those are ([own]): null, a pure virtual stub [PlainVtables] names
     * ([holdsPureVirtualStub]), or an unnamed one, which never returns and fills more than one slot. A function the
     * analysis wrongly thinks never returns fills one.
     */
    private fun pureSlots(
        targets: Map<PlainClass, List<Address>>,
        own: Map<PlainClass, List<Function?>>,
    ): Map<PlainClass, Set<Int>> {
        val slotsHeld = own.values.flatMap { fs -> fs.withIndex().mapNotNull { (i, f) -> f?.let { it to i } } }
            .groupBy({ it.first }, { it.second }).mapValues { it.value.toSet().size }
        return targets.mapValues { (cls, ats) ->
            ats.indices.filterTo(mutableSetOf()) { i ->
                val f = own.getValue(cls)[i]
                ats[i].offset == 0L || program.holdsPureVirtualStub(ats[i], PlainVtables::isPureVirtualStub) ||
                    (f != null && f.hasNoReturn() && slotsHeld.getValue(f) > 1)
            }
        }
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
        /** How many vbase offsets to read in front of a primary table. */
        const val MAX_VBASE_WORDS = 8

        /** How many bases deep [hasTableAt] looks. */
        const val MAX_BASE_DEPTH = 16

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

/**
 * The tables [PlainVtableParser.misplacedTables] finds: [secondaries] to move into the class each maps to, at the
 * offset of its base subobject there, and the [construction] vtables to seed a class from.
 */
class MisplacedTables(val secondaries: Map<Address, Pair<GhidraClass, Long>>, val construction: Set<Address>)

/**
 * The classes of [classes] whose table is really another class's secondary table, each mapped to that class
 * and to the offset of its base subobject.
 *
 * An MSVC constructor first calls each base's constructor, which stores the base's own table in the base
 * subobject. It then overwrites that with its own class's table for that subobject. Unlike an Itanium vtable
 * group, nothing in front of the table (no `offset_to_top`) says which class it belongs to. So a table counts
 * as a secondary when it is only ever stored past `this` + 0, it is the last table stored at that offset, every
 * function storing it also stores one class's primary table at `this` + 0, and that class has no table at the
 * offset yet.
 */
internal fun Program.msvcSecondaries(
    classes: List<PlainClass>,
    uses: Dissections,
): Map<Address, Pair<GhidraClass, Long>> {
    val ownStored = uses.stores.values.flatMapTo(mutableSetOf()) { it.classes }
    val placements = mutableMapOf<PlainClass, MutableSet<Pair<PlainClass, Long>>>()
    val notLast = mutableSetOf<ClassDecl>()
    for (stores in uses.stores.values) {
        // A primary table stored past `this` + 0, where no primary belongs, by the offset it is stored at.
        val elsewhere = stores.filter { it.home == 0L && it.offset > 0 }.groupBy({ it.offset }, { it.cls })
        for ((offset, stored) in elsewhere) {
            notLast += stored.dropLast(1)
            val table = stored.last() as? PlainClass ?: continue
            // Several primaries can be stored at `this` + 0 when a base's constructor is inlined first. The
            // owner is the most derived of them.
            val owner = longestPrimary(stores.classes)
            val placement = owner?.takeIf { o -> o.vftables.none { it.vfptrOffset(this) == offset } }
            placements.getOrPut(table) { mutableSetOf() } += (placement ?: table) to offset
        }
    }
    return classes.filter { it.vftables.size == 1 && it !in ownStored && it !in notLast }.mapNotNull { cls ->
        val (owner, offset) = placements[cls]?.singleOrNull()?.takeIf { it.first != cls } ?: return@mapNotNull null
        val ns = owner.ns as? GhidraClass ?: return@mapNotNull null
        cls.vftables.single().addressPoint to (ns to offset)
    }.toMap()
}
