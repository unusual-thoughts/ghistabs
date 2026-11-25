package ghicpp.abi.generic

import ghicpp.abi.functionSlots
import ghicpp.abi.vtableAt
import ghicpp.abi.vtableHeader
import ghicpp.dissect.Dissections
import ghicpp.dissect.ThisFunctionDissector
import ghicpp.dissect.classes
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidrakt.*

/** A base-object [structor] of [base], which a structor of [built] calls on its subobject at [offset]. */
internal class VttStructor(val structor: Function, val base: PlainClass, val built: PlainClass, val offset: Long)

/**
 * The base-object structors that load their vptrs from a VTT, each with its class.
 *
 * In Itanium, a base with virtual bases is built by a base-object constructor. The deriving class's
 * constructor passes it a pointer into the deriving class's VTT, where the base's sub-VTT starts. The
 * base-object constructor then stores the vptrs that the sub-VTT points at, which are construction vtables.
 * Code never takes those vtables' addresses directly, so neither the finder's seeds nor the stores that
 * [ThisFunctionDissector] reads say which class they belong to.
 *
 * The VTT pointer is a constant in the caller, and the construction vtable it leads to holds the base's
 * slots. So the base is the class whose primary table holds the same slots. A construction vtable no class holds
 * the slots of goes in [unmatched], for the finder to seed a class from.
 */
internal fun Program.findVttStructors(
    classes: List<PlainClass>,
    uses: Dissections,
    unmatched: MutableSet<Address>? = null,
): List<VttStructor> {
    val byTable = classes.associateBy { it.vftables.first().addressPoint }
    val primaries = classes.associateWith { functionSlots(it.vftables.first().addressPoint) }
    val found = mutableListOf<VttStructor>()
    for ((f, calls) in uses.vttCalls) {
        val built = uses.stores[f]?.classes?.let(::longestPrimary) ?: continue
        for (call in calls) {
            if (uses.stores[call.callee]?.classes.orEmpty().isNotEmpty()) continue
            val table = vtableAt(call.vtt)?.first?.takeIf(::isConstructionTable) ?: continue
            val base = byTable[table] ?: holding(functionSlots(table), primaries)
            if (base == null) unmatched?.add(table) else found += VttStructor(call.callee, base, built, call.offset)
        }
    }
    return found
}

/**
 * The class whose primary table holds the functions of [slots], each in the same slot. A null slot matches
 * anything, because a construction vtable may leave a destructor's slot null. When several classes match, it
 * picks the one with the shortest table, since classes deriving from it hold the same slots too. It returns
 * null when two matches are equally short.
 */
private fun holding(slots: List<Address>, primaries: Map<PlainClass, List<Address>>): PlainClass? {
    if (slots.none { it.offset != 0L }) return null
    val holders = primaries.filter { (_, own) ->
        own.size >= slots.size && slots.withIndex().all { (i, at) -> at.offset == 0L || own[i] == at }
    }
    val shortest = holders.values.minOfOrNull { it.size } ?: return null
    return holders.filterValues { it.size == shortest }.keys.singleOrNull()
}

private fun Program.functionSlots(at: Address) = functionSlots(at, PlainVtables).toList()

/**
 * Whether the [table] that a VTT word points at is a vtable's address point: in data, after a vtable header
 * ([hasVtableHeader]), with at least one function in its slots. Not every slot needs one, because a
 * construction vtable may leave its destructor slots null.
 */
private fun Program.isConstructionTable(table: Address): Boolean {
    val block = memory.getBlock(table) ?: return false
    return !block.isExecute && block.isInitialized && hasVtableHeader(table) &&
        functionSlots(table).any { it.offset != 0L }
}

/**
 * Whether an Itanium vtable header comes before [table]: an `offset_to_top` that a subobject could have, then
 * an RTTI word ([isRttiWord]).
 */
fun Program.hasVtableHeader(table: Address): Boolean = vtableHeader(table)?.let {
    it.offsetToTop <= 0 && -it.offsetToTop < PlainVtables.MAX_SUBOBJECT_OFFSET && isRttiPointer(it.rtti)
} == true

/** Whether the word at [at] is an RTTI word ([isRttiPointer]). */
fun Program.isRttiWord(at: Address) = pointerAt(at)?.let(::isRttiPointer) == true

/** Whether [p] may be an RTTI word's value: address 0, with no RTTI, or a pointer to data, a typeinfo. */
fun Program.isRttiPointer(p: Address) =
    p.offset == 0L || memory.getBlock(p)?.let { it.isInitialized && !it.isExecute } == true
