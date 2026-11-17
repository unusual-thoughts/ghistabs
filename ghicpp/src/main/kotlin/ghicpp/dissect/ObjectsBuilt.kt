package ghicpp.dissect

import ghicpp.ClassDecl
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

/**
 * Each object this function stores a vftable of [tables] ([vptrTables]) into where it belongs, by the class the
 * vftables say it is ([storedClass]), with the address it stores at each offset into it ([constantStores]): its
 * vptrs, and its vbtables among the rest. A virtual base's stores go into the object the vbtable stored beside its
 * vbptr puts the base in.
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
 * Where [this] points as a constructor reaches a virtual base, into the object [stores] puts a vbtable
 * in: `vbptr + vbtable[vdisp]`, the vbtable the one stored at the vbptr. Null for any other pointer.
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

/** The pointer [this] is loaded through, past casts. */
private fun Varnode.loaded(): Varnode? = when (def?.opcode) {
    PcodeOp.CAST -> def.getInput(0).loaded()
    PcodeOp.LOAD -> def.getInput(1)
    else -> null
}

/** Whether [at] may be an MSVC vbtable: its first entry, from the vbptr back to its subobject, is not positive. */
fun Program.mayBeVbtable(at: Address) = runCatching { memory.getInt(at) <= 0 }.getOrDefault(false)
