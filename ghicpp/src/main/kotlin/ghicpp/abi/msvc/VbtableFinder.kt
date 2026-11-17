package ghicpp.abi.msvc

import ghicpp.ClassDecl
import ghicpp.dissect.*
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

/**
 * Finds MSVC vbtables, which no RTTI points at: a function building a class, its constructor or one it
 * was inlined into, stores the class's vftables and vbtables into the object, so the address stored where
 * a vbptr sits, in an object the vftables say is of that class, is that class's vbtable there. It reads
 * what a [ThisFunctionDissector] found the vptr storers build ([Dissections.objectsBuilt]).
 */
class VbtableFinder(
    private val program: Program,
    /** Where each class with virtual bases has its vbptrs. */
    private val vbptrs: Map<ClassDecl, Set<Long>>,
) {
    /** Each of [vbptrs]' classes' vbtables, by where its vbptr sits in the class, where one of [uses] stores one. */
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
