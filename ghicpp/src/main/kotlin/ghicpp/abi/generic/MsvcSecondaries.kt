package ghicpp.abi.generic

import ghicpp.ClassDecl
import ghicpp.abi.slots
import ghicpp.dissect.Dissections
import ghicpp.dissect.classes
import ghidra.program.model.address.Address
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidrakt.*

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
internal fun msvcSecondaries(
    program: Program,
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
            val owner = program.longestPrimary(stores.classes)
            val placement = owner?.takeIf { o -> o.vftables.none { it.vfptrOffset(program) == offset } }
            placements.getOrPut(table) { mutableSetOf() } += (placement ?: table) to offset
        }
    }
    return classes.filter { it.vftables.size == 1 && it !in ownStored && it !in notLast }.mapNotNull { cls ->
        val (owner, offset) = placements[cls]?.singleOrNull()?.takeIf { it.first != cls } ?: return@mapNotNull null
        val ns = owner.ns as? GhidraClass ?: return@mapNotNull null
        cls.vftables.single().addressPoint to (ns to offset)
    }.toMap()
}
