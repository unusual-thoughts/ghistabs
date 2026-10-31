package ghistabs.cpp.abi.msvc

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.recover.PointerInto
import ghistabs.cpp.recover.pointerInto
import ghistabs.cpp.recover.storedClass
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/**
 * Finds MSVC vbtables, which no RTTI points at: a function building a class, its constructor or one it
 * was inlined into, stores the class's vftables and vbtables into the object, so the address stored where
 * a vbptr sits, in an object [classes]' vftables say is of that class, is that class's vbtable there.
 */
class Vbtables(private val program: Program, classes: Collection<ClassDecl>, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    /** Each vftable, by its address point: the class it serves and where in that class's object its vptr sits. */
    private val tables = classes.flatMap { cls ->
        cls.vftables.mapNotNull { r -> r.vfptrOffset(program)?.let { r.addressPoint to (cls to it) } }
    }.toMap()

    /** Each of [vbptrs]' classes' vbtables, by where its vbptr sits in the class, where a function stores one. */
    fun read(vbptrs: Map<ClassDecl, Set<Long>>, monitor: TaskMonitor): Map<ClassDecl, Map<Long, Address>> {
        val builders = tables.filterValues { (cls, _) -> cls in vbptrs }.keys
            .flatMap { table -> program.referenceManager.getReferencesTo(table).map { it.fromAddress } }
            .filter { program.listing.getInstructionAt(it) != null }
            .mapNotNullTo(mutableSetOf(), program.functionManager::getFunctionContaining)
        val found = mutableMapOf<ClassDecl, MutableMap<Long, Address>>()
        DecompInterface().useWith(program) { decomp ->
            for (func in builders) {
                if (monitor.isCancelled) break
                val high = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
                if (high == null) {
                    debug("vbtable-undecompiled", func.name, func.entryPoint)
                    continue
                }
                for ((cls, stored) in high.objectsBuilt()) {
                    for (at in vbptrs[cls].orEmpty()) {
                        val vbtable = stored[at]?.takeIf(::mayBeVbtable) ?: continue
                        found.getOrPut(cls) { mutableMapOf() }.putIfAbsent(at, vbtable)
                    }
                }
            }
        }
        return found
    }

    /**
     * Each object this function stores a vftable into where it belongs, by the class the vftables say it
     * is ([storedClass]), with the address it stores at each offset into it.
     */
    private fun HighFunction.objectsBuilt(): Map<ClassDecl, Map<Long, Address>> {
        val stores = mutableMapOf<Varnode, MutableMap<Long, Address>>()
        for (op in pcodeOps) {
            if (op.opcode != PcodeOp.STORE) continue
            val value = op.getInput(2).constant()?.let(::asAddress) ?: continue
            val (root, offset) = op.getInput(1).pointerInto()
            stores.getOrPut(root) { mutableMapOf() }[offset] = value
        }
        // A virtual base's vptr goes where the vbtable stored beside it puts the base: into that object.
        for (root in stores.keys.toList()) {
            val (into, at) = root.throughVbtable(stores) ?: continue
            val moved = stores.remove(root).orEmpty()
            for ((offset, value) in moved) stores.getOrPut(into) { mutableMapOf() }[at + offset] = value
        }
        return stores.values.mapNotNull { stored ->
            val classes = stored.mapNotNullTo(mutableSetOf()) { (at, value) ->
                tables[value]?.takeIf { (_, vptrAt) -> vptrAt == at }?.first
            }
            storedClass(classes)?.let { it to stored }
        }.toMap()
    }

    /**
     * Where [this] points as a constructor reaches a virtual base, into the object [stores] puts a vbtable
     * in: `vbptr + vbtable[vdisp]`, the vbtable the one stored at the vbptr. Null for any other pointer.
     */
    private fun Varnode.throughVbtable(stores: Map<Varnode, Map<Long, Address>>): PointerInto? {
        val sum = def?.takeIf { it.opcode == PcodeOp.INT_ADD || it.opcode == PcodeOp.PTRADD } ?: return null
        if (sum.opcode == PcodeOp.PTRADD && sum.getInput(2).let { !it.isConstant || it.offset != 1L }) return null
        return listOf(0, 1).firstNotNullOfOrNull { i ->
            val vbptr = sum.getInput(i).pointerInto()
            val (vbtableAt, vdisp) = sum.getInput(1 - i).loaded()?.pointerInto() ?: return@firstNotNullOfOrNull null
            val (root, pdisp) = vbtableAt.loaded()?.pointerInto() ?: return@firstNotNullOfOrNull null
            val vbtable = stores[root]?.get(pdisp)?.takeIf { root == vbptr.root && pdisp == vbptr.offset }
                ?.takeIf(::mayBeVbtable)
            vbtable?.let { runCatching { program.memory.getInt(it.add(vdisp)) }.getOrNull() }
                ?.let { PointerInto(root, pdisp + it) }
        }
    }

    /** The pointer [this] is loaded through, past copies and casts. */
    private fun Varnode.loaded(): Varnode? = when (def?.opcode) {
        PcodeOp.COPY, PcodeOp.CAST -> def.getInput(0).loaded()
        PcodeOp.LOAD -> def.getInput(1)
        else -> null
    }

    /** The constant [this] is, the decompiler's `&DAT_…` (`PTRSUB 0, addr`) included. */
    private fun Varnode.constant(): Long? = when {
        isConstant -> offset

        def?.opcode == PcodeOp.PTRSUB && def.getInput(0).let { it.isConstant && it.offset == 0L } ->
            def.getInput(1).takeIf { it.isConstant }?.offset

        def?.opcode == PcodeOp.COPY -> def.getInput(0).takeIf { it.isConstant }?.offset

        else -> null
    }

    private fun asAddress(value: Long) =
        runCatching { program.addressFactory.defaultAddressSpace.getAddress(value) }.getOrNull()
            ?.takeIf(program.memory::contains)

    /** Whether [at] may be a vbtable: its first entry, from the vbptr back to its subobject, is not positive. */
    private fun mayBeVbtable(at: Address) = runCatching { program.memory.getInt(at) <= 0 }.getOrDefault(false)

    private companion object {
        const val DECOMPILE_TIMEOUT_SECONDS = 30
    }
}
