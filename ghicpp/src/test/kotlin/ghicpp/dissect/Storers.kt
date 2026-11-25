package ghicpp.dissect

import ghicpp.ClassDecl
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program

/**
 * A dissection of a function that calls each of [pre] on `this` + its offset, stores the vptrs of [classes] at
 * `this` + 0, where they belong, then calls each of [post], in that order, and whose calls by offset are
 * [subobjectCalls]. The addresses are made up, in order, and need not be the function's.
 */
internal fun Program.storer(
    classes: Set<ClassDecl>,
    pre: List<Pair<Long, Function>> = emptyList(),
    post: List<Pair<Long, Function>> = emptyList(),
    subobjectCalls: Map<Long, Set<Function>> = emptyMap(),
): DissectionCache.Dissection {
    val space = addressFactory.defaultAddressSpace
    val at = generateSequence(0x500000L) { it + 1 }.map(space::getAddress).iterator()
    val before = pre.map { (offset, f) -> ObjectCall(at.next(), f, CalledObject.This, offset) }
    val store = at.next()
    val after = post.map { (offset, f) -> ObjectCall(at.next(), f, CalledObject.This, offset) }
    return DissectionCache.Dissection(
        classes.map { VptrStore(store, 0, it, 0) },
        subobjectCalls,
        objectCalls = before + after,
    )
}
