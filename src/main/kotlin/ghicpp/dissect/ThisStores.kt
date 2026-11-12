package ghicpp.dissect

import ghicpp.ClassDecl
import ghicpp.abi.StructorConvention
import ghicpp.abi.StructorRole
import ghicpp.abi.StructorRole.*
import ghicpp.introducingClass
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.NoisyStructureBuilder
import ghidra.program.model.listing.Function
import ghistabs.withLength

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
 * The [classes] whose vtables a function stores into `this` where they belong, and what it calls on `this` or a
 * subobject of it [before] the first of those stores and [after] the last.
 */
data class VptrStores(
    val classes: Set<ClassDecl> = emptySet(),
    val before: Set<Function> = emptySet(),
    val after: Set<Function> = emptySet(),
)

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
 * What each decompiled function does with `this`: the vptrs it stores ([stores]), the functions it calls on
 * `this` or a subobject of it, by offset into it ([subobjectCalls]), and the fields it stores through `this`, by
 * offset ([thisStores]), and the constructors inlined after an `operator new` ([inlined]).
 */
class Dissections internal constructor(from: Map<Function, DissectionCache.Dissection> = emptyMap()) {
    val stores: Map<Function, VptrStores> = from.mapNotNull { (f, r) -> r.stores?.let { f to it } }.toMap()
    val subobjectCalls: Map<Function, Map<Long, Set<Function>>> = from.mapValues { (_, r) -> r.subobjectCalls }
    val thisStores: ThisStores = from.mapValues { (_, r) -> r.thisStores }
    val inlined: List<InlinedConstruction> = from.flatMap { (_, r) -> r.inlined }

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
) {
    /** The size each class is allocated with where a constructor is inlined after its `operator new`, the largest. */
    val inlinedSizes: Map<ClassDecl, Long> by lazy {
        inlined.groupBy({ it.built }, { it.size }).mapValues { (_, sizes) -> sizes.max() }
    }

    val inlinedByFunction by lazy { inlined.groupBy { it.function } }

    /** Each constructor, by the class it builds. */
    val constructors = roles.filterValues { it.second == CONSTRUCTOR }.mapValues { it.value.first }

    /**
     * The fields each class's constructors, its own and those folded into another's, store through `this`, by
     * offset into it: its own fields where nothing else is laid, and how large it is at least. Where two
     * constructors disagree, [NoisyStructureBuilder] keeps the more specific type, as it does for one.
     */
    val constructorStores: Map<ClassDecl, Stores> by lazy {
        val built = constructors.map { (f, cls) -> f to cls } + folded.flatMap { (f, cs) -> cs.map { f to it } }
        val byClass = built.groupBy({ it.second }, { thisStores[it.first].orEmpty() })
        val parts = inlined.flatMap { it.parts }.groupBy({ it.cls }, { it.fields })
        (byClass.keys + parts.keys).associateWith { cls ->
            (byClass[cls].orEmpty() + parts[cls].orEmpty()).mergedStores()
        }
    }
}
