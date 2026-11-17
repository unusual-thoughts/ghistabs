package ghicpp.abi.msvc

import ghicpp.ClassDecl
import ghicpp.dissect.*
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

/**
 * Finds MSVC vbtables, which no RTTI points at.
 *
 * A function that builds an object, such as its class's constructor or a function the constructor was inlined
 * into, stores both the vftables and the vbtables into it. The vftables tell which class the object is. So when
 * that class has a vbptr at some offset, the address stored at that offset is the class's vbtable.
 *
 * The objects each function builds come from a [ThisFunctionDissector] ([Dissections.objectsBuilt]).
 */
class VbtableFinder(
    private val program: Program,
    /** Where each class with virtual bases has its vbptrs. */
    private val vbptrs: Map<ClassDecl, Set<Long>>,
) {
    /**
     * The vbtables that the functions in [uses] store, for each class in [vbptrs]. Each vbtable is keyed by the
     * offset of its vbptr in the class.
     */
    fun find(uses: Dissections): Map<ClassDecl, Map<Long, Address>> {
        val vbtables = mutableMapOf<ClassDecl, MutableMap<Long, Address>>()
        for (built in uses.objectsBuilt.values) {
            for ((cls, stored) in built) {
                for (at in vbptrs[cls].orEmpty()) {
                    val vbtable = stored[at]?.takeIf(program::mayBeVbtable) ?: continue
                    vbtables.getOrPut(cls) { mutableMapOf() }.putIfAbsent(at, vbtable)
                }
            }
        }
        return vbtables
    }
}
