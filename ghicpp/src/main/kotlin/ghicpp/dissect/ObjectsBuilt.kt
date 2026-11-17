package ghicpp.dissect

import ghicpp.ClassDecl
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

/**
 * The objects this function builds, found from the vftables of [tables] ([vptrTables]) it stores into them.
 *
 * An object counts when a vftable is stored at the offset where it belongs. The vftables stored into the object
 * tell its class ([storedClass]). For each object, the result maps that class to every constant address the
 * function stores into the object, by offset ([constantStores]). These include the vptrs and, for MSVC, the
 * vbtables.
 *
 * A constructor reaches a virtual base through the vbtable it stored earlier, so its stores into that base are
 * not at a constant offset from `this`. [throughVbtable] resolves them, so that they count as stores into the
 * object being built, at the base's offset.
 */
internal fun HighFunction.objectsBuilt(
    tables: Map<Address, Pair<ClassDecl, Long>>,
): Map<ClassDecl, Map<Long, Address>> {
    val objects = constantStores().toMutableMap()
    for (root in objects.keys.toList()) {
        val (into, at) = root.throughVbtable(function.program, objects) ?: continue
        val moved = objects.remove(root).orEmpty()
        objects[into] = objects[into].orEmpty() + moved.mapKeys { (offset, _) -> at + offset }
    }
    return objects.values.mapNotNull { stored ->
        val classes = stored.mapNotNullTo(mutableSetOf()) { (at, value) ->
            tables[value]?.takeIf { (_, vptrAt) -> vptrAt == at }?.first
        }
        storedClass(classes)?.to(stored)
    }.toMap()
}

/**
 * Where [this] points, when it is a pointer to a virtual base that a constructor computes as
 * `vbptr + vbtable[vdisp]`.
 *
 * The vbtable must be the one [stores] says the function stored at that vbptr. The result is the object holding
 * the vbptr, at the offset of the virtual base inside it. Null when [this] is not such a pointer.
 */
private fun HighVariable.throughVbtable(program: Program, stores: Map<HighVariable, Map<Long, Address>>): PointerInto? {
    val sum = instances.firstNotNullOfOrNull { v ->
        v.def?.takeIf { it.opcode == PcodeOp.INT_ADD || it.opcode == PcodeOp.PTRADD }
    } ?: return null
    if (sum.opcode == PcodeOp.PTRADD && sum.getInput(2).let { !it.isConstant || it.offset != 1L }) return null
    return listOf(0, 1).firstNotNullOfOrNull { i ->
        val vbptr = sum.getInput(i).pointerInto() ?: return@firstNotNullOfOrNull null
        val (vbtableAt, vdisp) = sum.getInput(1 - i).loaded()?.pointerInto() ?: return@firstNotNullOfOrNull null
        val (root, pdisp) = vbtableAt.instances.firstNotNullOfOrNull { it.loaded() }?.pointerInto()
            ?: return@firstNotNullOfOrNull null
        val vbtable = stores[root]?.get(pdisp)?.takeIf { root == vbptr.root && pdisp == vbptr.offset }
            ?.takeIf(program::mayBeVbtable)
        vbtable?.let { runCatching { program.memory.getInt(it.add(vdisp)) }.getOrNull() }
            ?.let { PointerInto(root, pdisp + it) }
    }
}

/** The address that [this] was loaded from, looking through casts. Null when [this] was not loaded. */
private fun Varnode.loaded(): Varnode? = when (def?.opcode) {
    PcodeOp.CAST -> def.getInput(0).loaded()
    PcodeOp.LOAD -> def.getInput(1)
    else -> null
}

/**
 * Whether [at] may be an MSVC vbtable. A vbtable's first entry is the offset from the vbptr back to the start of
 * its subobject, so it is zero or negative.
 */
fun Program.mayBeVbtable(at: Address) = runCatching { memory.getInt(at) <= 0 }.getOrDefault(false)
