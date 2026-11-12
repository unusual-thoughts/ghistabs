package ghicpp.structors

import ghicpp.ClassDecl
import ghicpp.abi.StructorConvention
import ghicpp.abi.StructorRole
import ghicpp.abi.StructorRole.*
import ghicpp.introducingClass
import ghicpp.storedClass
import ghidra.program.model.data.DataType
import ghidra.program.model.listing.Function

/**
 * What each decompiled function does with `this`: the vptrs it stores ([stores]), the functions it calls on
 * `this` or a subobject of it, by offset into it ([subobjectCalls]), and the fields it stores through `this`, by
 * offset ([thisStores]), and the constructors inlined after an `operator new` ([inlined]).
 */
class ThisUses(
    val stores: Map<Function, VptrStores>,
    val subobjectCalls: Map<Function, Map<Long, Set<Function>>>,
    val thisStores: Map<Function, Map<Int, DataType>> = emptyMap(),
    val inlined: List<InlinedConstruction> = emptyList(),
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
