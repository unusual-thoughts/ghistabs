package ghicpp.abi.generic

import ghicpp.ClassDecl
import ghicpp.abi.functionSlots
import ghicpp.abi.vtableAt
import ghicpp.dissect.Dissections
import ghicpp.dissect.ThisFunctionDissector
import ghicpp.recover.GenericVftableFinder
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidrakt.*

/** A base-object [structor] of [base], which a structor of [built] calls on its subobject at [offset]. */
internal class VttStructor(val structor: Function, val base: PlainClass, val built: PlainClass, val offset: Long)

/** Finds the base-object structors of [program]'s plain classes that take a VTT ([find]). */
internal class VttStructors(private val program: Program) {
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
     * slots. So the base is the class whose primary table holds the same slots. If no class does, [finder] seeds
     * a new one from the construction vtable. Returns null when it seeded any class, so that the classes are read
     * again. It seeds nothing when there is no [finder].
     */
    fun find(classes: List<PlainClass>, uses: Dissections, finder: GenericVftableFinder?): List<VttStructor>? {
        val byTable = classes.associateBy { it.vftables.first().addressPoint }
        val primaries = classes.associateWith { functionSlots(it.vftables.first().addressPoint) }
        val found = mutableListOf<VttStructor>()
        var seeded = false
        for ((f, calls) in uses.vttCalls) {
            val built = uses.stores[f]?.classes?.let(program::longestPrimary) ?: continue
            for (call in calls) {
                if (uses.stores[call.callee]?.classes.orEmpty().isNotEmpty()) continue
                val table = program.vtableAt(call.vtt)?.first?.takeIf(::isConstructionTable) ?: continue
                val base = byTable[table] ?: holding(functionSlots(table), primaries)
                if (base == null) {
                    if (finder?.seedConstruction(table) == true) seeded = true
                    continue
                }
                found += VttStructor(call.callee, base, built, call.offset)
            }
        }
        return found.takeUnless { seeded }
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

    private fun functionSlots(at: Address) = program.functionSlots(at, PlainVtables).toList()

    /**
     * Whether the [table] that a VTT word points at is a vtable's address point: in data, after a vtable header
     * ([hasVtableHeader]), with at least one function in its slots. Not every slot needs one, because a
     * construction vtable may leave its destructor slots null.
     */
    private fun isConstructionTable(table: Address): Boolean {
        val block = program.memory.getBlock(table) ?: return false
        return !block.isExecute && block.isInitialized && program.hasVtableHeader(table) &&
            functionSlots(table).any { it.offset != 0L }
    }
}
