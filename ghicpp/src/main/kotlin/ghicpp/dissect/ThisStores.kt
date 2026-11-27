package ghicpp.dissect

import ghicpp.*
import ghicpp.StructorRole.*
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.NoisyStructureBuilder
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DummySink

/** Stores to a `this` variable within one method */
typealias Stores = Map<Int, DataType>

/** Stores to a `this` variable across multiple methods */
typealias ThisStores = Map<Function, Stores>

/** [this] by offset, merged in a [NoisyStructureBuilder], which keeps the more specific type where two disagree. */
internal fun Iterable<Stores>.mergedStores(): Stores {
    val fields = NoisyStructureBuilder()
    for (store in this) store.forEach { (at, dt) -> fields.addDataType(at.toLong(), dt) }
    return fields.iterator().asSequence().associate { (at, dt) -> at.toInt() to dt }
}

/** [this] with the arrays [fills] in place of what it stores where they lie, but at each one's start. */
internal fun Stores.withFills(fills: Stores): Stores {
    if (fills.isEmpty()) return this
    val covered = filterKeys { at -> fills.none { (start, dt) -> at in start.withLength(dt.length) } }
    return covered + fills
}

/**
 * A store, at [at], of a table of [cls] into `this` + [offset]. [cls]'s vptr belongs at `this` + [home], and
 * [throughVbtable] says the function read [offset] from a vbtable, so that it is a virtual base's.
 */
data class VptrStore(
    val at: Address,
    val offset: Long,
    val cls: ClassDecl,
    val home: Long,
    val throughVbtable: Boolean = false,
)

/**
 * These stores, each store of a primary table that a function makes through a vbtable, at `this` + k, where it
 * stores no table at `this` + 0, taken as one where the table belongs: MSVC gives a class whose virtuals all
 * override its virtual bases' no vfptr of its own, so its only table is the one for the virtual base at k. Not where
 * what the function calls on `this` + k stores the same table, as a virtual base's own structor does.
 */
private fun Map<Function, List<VptrStore>>.withVbaseHomes(
    from: Map<Function, DissectionCache.Dissection>,
): Map<Function, List<VptrStore>> = mapValues { (f, stored) ->
    if (stored.any { it.offset == 0L && !it.throughVbtable }) return@mapValues stored
    val calls = from[f]?.subobjectCalls.orEmpty()
    stored.map { s ->
        val vbase = s.throughVbtable && s.home == 0L && s.offset > 0L
        if (vbase && calls[s.offset].orEmpty().none { g -> this[g].orEmpty().any { it.cls == s.cls } }) {
            s.copy(home = s.offset)
        } else {
            s
        }
    }
}

/** The stores of a vptr where it belongs. */
val List<VptrStore>.own: List<VptrStore> get() = filter { it.offset == it.home }

/** The classes whose vptrs these store where they belong. */
val List<VptrStore>.classes: Set<ClassDecl> get() = own.mapTo(mutableSetOf()) { it.cls }

/** The functions these calls call. */
val List<ObjectCall>.callees: Set<Function> get() = mapTo(mutableSetOf()) { it.callee }

/**
 * A call of [callee] on `this` + [offset] that passes the address [vtt] after `this`. An Itanium structor calls
 * the base-object structor of a base that has virtual bases this way, with [vtt] pointing at the base's sub-VTT.
 */
data class VttCall(val offset: Long, val callee: Function, val vtt: Address)

/**
 * One class's share of an [InlinedConstruction]: what the code from its vptr store up to the next class's calls on
 * the allocation, by offset into it ([calls]), and the fields it stores there ([fields]).
 */
class InlinedPart(val cls: ClassDecl, val calls: Map<Long, Set<Function>>, val fields: Stores)

/**
 * A constructor the compiler inlined into [function] after the `operator new(size)` call at [at]: the vptrs it
 * stores at the start of the fresh allocation, each class's [parts] in the order it stores them. A constructor
 * stores a base's vptr before the vptr of the class deriving from it, so the last is the class it builds
 * ([built]), and [size] is how large that is.
 */
class InlinedConstruction(val function: Function, val at: Address, val size: Long, val parts: List<InlinedPart>) {
    /** The classes whose vptrs it stores, bases first. */
    val order get() = parts.map { it.cls }

    /** The class it builds: the one the others are bases of, else the last stored. */
    val built: ClassDecl get() = storedClass(order.toSet()) ?: parts.last().cls
}

/**
 * What each decompiled function does with `this`: the vptrs it stores, in address order ([stores]), the
 * functions it calls on `this` or a subobject of it, by offset into it ([subobjectCalls]), and the fields it
 * stores through `this`, by offset ([thisStores]), and the constructors inlined after an `operator new`
 * ([inlined]).
 */
class Dissections internal constructor(from: Map<Function, DissectionCache.Dissection> = emptyMap()) {
    val stores: Map<Function, List<VptrStore>> =
        from.mapNotNull { (f, r) -> r.stores?.let { f to it } }.toMap().withVbaseHomes(from)
    val subobjectCalls: Map<Function, Map<Long, Set<Function>>> = from.mapValues { (_, r) -> r.subobjectCalls }
    val thisStores: ThisStores = from.mapValues { (_, r) -> r.thisStores }
    val inlined: List<InlinedConstruction> = from.flatMap { (_, r) -> r.inlined }

    /** The calls each makes on an object, its own `this` or another, by the object's `this` argument. */
    val objectCalls: Map<Function, List<ObjectCall>> = from.mapValues { (_, r) -> r.objectCalls }

    private fun Function.callsOnThis() = objectCalls[this]?.filter { it.obj == CalledObject.This && !it.slot }.orEmpty()

    /** The constants each function stores into `this` that may be vbtables, by offset. */
    val vbtables: Map<Function, Map<Long, Address>> =
        from.mapValues { (_, r) -> r.vbtables }.filterValues { it.isNotEmpty() }

    /**
     * The objects each vptr storer builds ([objectsBuilt]). For each object, maps its class to the constant
     * addresses the function stores into it, by offset.
     */
    val objectsBuilt: Map<Function, Map<ClassDecl, Map<Long, Address>>> =
        from.filterValues { it.objectsBuilt.isNotEmpty() }.mapValues { (_, r) -> r.objectsBuilt }

    /** The calls each function makes on `this` that pass a constant address after `this` ([VttCall]). */
    val vttCalls: Map<Function, List<VttCall>> = objectCalls.mapValues { (_, calls) ->
        calls.mapNotNull { c -> c.next?.takeIf { c.obj == CalledObject.This }?.let { VttCall(c.offset, c.callee, it) } }
    }.filterValues { it.isNotEmpty() }

    /** The calls [this] makes on `this` or a subobject of it before the first store of a vptr where it belongs. */
    fun Function.pre(): List<ObjectCall> = stores[this]?.own?.firstOrNull()?.at?.let { first ->
        callsOnThis().filter { it.at < first }
    }.orEmpty()

    /** The calls [this] makes on `this` or a subobject of it after the last store of a vptr where it belongs. */
    fun Function.post(): List<ObjectCall> = stores[this]?.own?.lastOrNull()?.at?.let { last ->
        callsOnThis().filter { it.at > last }
    }.orEmpty()

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
     * the reverse destroys. A storer none of that sorts destroys if it calls on its members from the last down
     * ([destroysDownwards]), and that may sort more. Every storer left builds.
     */
    private fun MutableMap<Function, Pair<ClassDecl, StructorRole>>.sortByCalls(owners: Map<Function, ClassDecl>) {
        do {
            sortByBaseCalls(owners)
            val downwards = owners.filter { (f, _) -> f !in this && destroysDownwards(f) }
            for ((f, cls) in downwards) this[f] = cls to DESTRUCTOR
        } while (downwards.isNotEmpty())
        for ((f, cls) in owners) putIfAbsent(f, cls to CONSTRUCTOR)
    }

    /**
     * Whether the calls a storer makes on its members after its stores, each offset where it first calls on one,
     * go from the highest offset down, two or more. A constructor builds its members in the order they are laid,
     * and a destructor destroys them the other way. A landing pad destroying the members built again comes later.
     * A call on `this` + 0 is a method of the class's own or a base's, which a constructor's body calls after
     * building its members, so it says nothing of the order.
     */
    private fun destroysDownwards(f: Function): Boolean {
        val firsts = f.post().map { it.offset }.filter { it > 0 }.distinct()
        return firsts.size >= 2 && firsts.zipWithNext().all { (a, b) -> a > b }
    }

    private fun MutableMap<Function, Pair<ClassDecl, StructorRole>>.sortByBaseCalls(owners: Map<Function, ClassDecl>) {
        fun basesOf(cls: ClassDecl, fs: Set<Function>, not: StructorRole) = fs.filter { g ->
            owners[g]?.let { it != cls && cls.derivesFrom(it) } == true && this[g]?.second != not
        }
        do {
            val known = size
            for ((f, cls) in owners) {
                if (f in this) continue
                val role = when {
                    basesOf(cls, f.pre().callees, DESTRUCTOR).isNotEmpty() -> CONSTRUCTOR
                    basesOf(cls, f.post().callees, CONSTRUCTOR).isNotEmpty() -> DESTRUCTOR
                    else -> byKnownCalls(f)
                }
                role?.let { this[f] = cls to it }
            }
            for ((f, entry) in toList()) {
                val (cls, role) = entry
                val bases = when (role) {
                    CONSTRUCTOR -> basesOf(cls, f.pre().callees, DESTRUCTOR)
                    DESTRUCTOR -> basesOf(cls, thisCalls[f].orEmpty() + f.post().callees, CONSTRUCTOR)
                    else -> emptyList()
                }
                for (g in bases) putIfAbsent(g, owners.getValue(g) to role)
            }
        } while (size != known)
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

/**
 * What [ThisFunctionDissector.find] found: each structor's class and role ([roles]), each constructor a linker folded
 * into another class's that builds [folded] classes too, the fields each function read stores through
 * `this`, and the constructors inlined after an `operator new` ([inlined]).
 */
class FoundStructors(
    val roles: Map<Function, Pair<ClassDecl, StructorRole>>,
    val folded: Map<Function, Set<ClassDecl>>,
    private val thisStores: ThisStores,
    /** What each function read calls on `this` or a subobject of it, by offset into it, in the order it calls. */
    val subobjectCalls: Map<Function, Map<Long, Set<Function>>> = emptyMap(),
    val inlined: List<InlinedConstruction> = emptyList(),
    /** The functions each constructor calls on `this` + 0 to set up its fields, which are not structors. */
    private val helpers: Map<Function, List<Function>> = emptyMap(),
) {
    /** The size each class is allocated with where a constructor is inlined after its `operator new`, the largest. */
    val inlinedSizes: Map<ClassDecl, Long> by lazy {
        inlined.groupBy({ it.built }, { it.size }).mapValues { (_, sizes) -> sizes.max() }
    }

    val inlinedByFunction by lazy { inlined.groupBy { it.function } }

    /** Each constructor, by the class it builds. */
    val constructors = roles.filterValues { it.second == CONSTRUCTOR }.mapValues { it.value.first }

    /**
     * The member objects each class's constructors build and destructors destroy, each with its offset: the class
     * of the constructor found here that a constructor first calls on `this` + k, past `this` + 0, or of the
     * destructor that a destructor last calls there, where that class is another. A base's subobject there is one
     * too, as far as the class's size goes.
     */
    val memberObjects: Map<ClassDecl, List<Pair<ClassDecl, Long>>> by lazy {
        roles.entries.groupBy({ it.value.first }) { (f, by) ->
            val (cls, role) = by
            subobjectCalls[f].orEmpty().filterKeys { it > 0 }.mapNotNull { (at, called) ->
                val member = when (role) {
                    CONSTRUCTOR -> called.first()
                    DESTRUCTOR -> called.last()
                    else -> return@mapNotNull null
                }
                roles[member]?.takeIf { (m, r) -> r == role && m != cls }?.let { it.first to at }
            }
        }.mapValues { (_, found) -> found.flatten().distinct() }.filterValues { it.isNotEmpty() }
    }

    /**
     * The fields each class's constructors, its own and those folded into another's, store through `this`, by
     * offset into it, and the methods they call on `this` to set them up ([helpers]): its own fields where nothing
     * else is laid, and how large it is at least. Where two
     * constructors disagree, [NoisyStructureBuilder] keeps the more specific type, as it does for one.
     */
    val constructorStores: Map<ClassDecl, Stores> by lazy {
        val built = constructors.map { (f, cls) -> f to cls } + folded.flatMap { (f, cs) -> cs.map { f to it } }
        val byClass = built.groupBy({ it.second }, { (f, _) ->
            (listOf(f) + helpers[f].orEmpty()).map { thisStores[it].orEmpty() }.mergedStores()
        })
        val parts = inlined.flatMap { it.parts }.groupBy({ it.cls }, { it.fields })
        (byClass.keys + parts.keys).associateWith { cls ->
            (byClass[cls].orEmpty() + parts[cls].orEmpty()).mergedStores()
        }
    }
}

/**
 * Fills each of this class struct's own `<Class>_data` structs ([ownData]) with the fields of [store] it holds,
 * as Auto Fill in Structure fills one: where a field is there already, [NoisyStructureBuilder] keeps the more
 * specific type, and the field keeps its name
 */
internal fun Structure.fillData(store: Stores) {
    for ((offset, data) in ownData()) data.fillRun(offset, store, flat = data === this)
}

/**
 * Fills this, the struct of a class's own fields at [offset] into it, with the fields of [store] it holds, as
 * [fillData]. Where it is the class struct itself ([ghicpp.isFlatInferred]), a new field is marked as inferred.
 */
internal fun Structure.fillRun(offset: Int, store: Stores, flat: Boolean) {
    val inside = store.filter { (at, dt) -> offset.withLength(length).includes(at.withLength(dt.length)) }
    val merged = NoisyStructureBuilder().also { it.populateOriginalStructure(this) }
    for ((at, dt) in inside) merged.addDataType(at.toLong() - offset, dt)
    val mark = ClassNaming.INFERRED.takeIf { flat }
    for ((at, dt) in merged.iterator()) {
        val old = getComponentAt(at.toInt())
        if (at + dt.length > length || old?.dataType?.isEquivalent(dt) == true) continue
        val name = old?.fieldName ?: ClassNaming.fieldName(offset + at.toInt())
        replaceAtOffset(at.toInt(), dt, dt.length, name, old?.comment ?: mark)
    }
}

/**
 * Retypes [ns]'s own fields off what [methods] load and store through `this`, decompiled again, as the class pass
 * fills them: the `<Class>_data` structs its struct holds take the more specific type, and keep names and comments.
 */
fun Program.updateFieldTypes(ns: GhidraClass, methods: Collection<Function>, monitor: TaskMonitor) {
    val struct = classStruct(ns) ?: return
    struct.fillData(
        ThisFunctionDissector(this, emptyList(), DummySink).thisFields(methods, monitor).values.mergedStores(),
    )
}
