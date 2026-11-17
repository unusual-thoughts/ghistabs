package ghicpp.abi.msvc

import ghicpp.ClassDecl
import ghicpp.dissect.*
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

/**
 * Finds the MSVC vbtables that the functions in [uses] store, for each class in [vbptrs], which gives where each
 * class has its vbptrs. Each vbtable is keyed by the offset of its vbptr in the class.
 *
 * No RTTI points at a vbtable. A function that builds an object, such as its class's constructor or a function the
 * constructor was inlined into, stores both the vftables and the vbtables into it, and the vftables tell which
 * class the object is ([Dissections.objectsBuilt]). So when that class has a vbptr at some offset, the address
 * stored at that offset is the class's vbtable.
 */
fun Program.findVbtables(uses: Dissections, vbptrs: Map<ClassDecl, Set<Long>>): Map<ClassDecl, Map<Long, Address>> =
    buildMap<ClassDecl, MutableMap<Long, Address>> {
        for ((cls, stored) in uses.objectsBuilt.values.flatMap { it.entries }) {
            for (at in vbptrs[cls].orEmpty()) {
                val vbtable = stored[at]?.takeIf(::mayBeVbtable) ?: continue
                getOrPut(cls) { mutableMapOf() }.putIfAbsent(at, vbtable)
            }
        }
    }
