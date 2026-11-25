package ghicpp.dissect

import ghicpp.ClassDecl
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

/** The address that [this] was loaded from, looking through casts. Null when [this] was not loaded. */
private fun Varnode.loaded(): Varnode? = when (def?.opcode) {
    PcodeOp.CAST -> def.getInput(0).loaded()
    PcodeOp.LOAD -> def.getInput(1)
    else -> null
}

private fun Varnode.isConstantPointer(): Boolean = isConstant ||
    def?.let { it.opcode == PcodeOp.PTRSUB || it.opcode == PcodeOp.COPY || it.opcode == PcodeOp.CAST } == true

/**
 * Whether [at] may be an MSVC vbtable. A vbtable's first entry is the offset from the vbptr back to the start of
 * its subobject, so it is zero or negative.
 */
private fun Program.mayBeVbtable(at: Address) = runCatching { memory.getInt(at) <= 0 }.getOrDefault(false)

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

/**
 * Where [this] points, when it is a pointer to a virtual base that a constructor computes as
 * `vbptr + vbtable[vdisp]`.
 *
 * The vbtable must be the one [stores] says the function stored at that vbptr. The result is the object holding
 * the vbptr, at the offset of the virtual base inside it. Null when [this] is not such a pointer.
 */
fun HighVariable.throughVbtable(program: Program, stores: Map<HighVariable, Map<Long, Address>>): PointerInto? {
    val (first, second) = instances.firstNotNullOfOrNull { v ->
        v.def?.takeIf { it.opcode == PcodeOp.INT_ADD || it.opcode == PcodeOp.PTRADD }
    }?.takeUnless { sum ->
        sum.opcode == PcodeOp.PTRADD && sum.getInput(2).let { !it.isConstant || it.offset != 1L }
    }?.inputs ?: return null

    fun resolve(ptr: Varnode, table: Varnode): PointerInto? {
        val vbptr = ptr.pointerInto() ?: return null
        val (vbtableAt, vdisp) = table.loaded()?.pointerInto() ?: return null
        if (vbtableAt.instances.firstNotNullOfOrNull { it.loaded() }?.pointerInto() != vbptr) return null
        val (root, pdisp) = vbptr
        return stores[root]?.get(pdisp)
            ?.takeIf(program::mayBeVbtable)
            ?.let { runCatching { program.memory.getInt(it.add(vdisp)) }.getOrNull() }
            ?.let { PointerInto(root, pdisp + it) }
    }
    return resolve(first, second) ?: resolve(second, first)
}

/**
 * Reads a pointer's value as the variable it points into plus a constant offset. [vbtables] holds the vbtables
 * the function stored into [self], by offset. Loading one back gives that vbtable, and loading an entry from it
 * gives the entry's value.
 */
private class VbaseReader(
    private val program: Program,
    private val self: HighVariable,
    private val vbtables: Map<Long, Address>,
) {
    /**
     * A value as [VbaseReader] reads it: [root] plus [offset], or just the constant [offset] when [root] is null.
     * With [vbtable], the value is [offset] bytes into that vbtable, one that `self` holds. [throughVbtable] means a
     * vbtable entry was added into it.
     */
    data class Read(
        val root: HighVariable?,
        val offset: Long,
        val throughVbtable: Boolean = false,
        val vbtable: Address? = null,
    )

    fun read(v: Varnode, depth: Int = 0): Read? {
        if (depth > MAX_DEPTH) return null
        if (v.isConstant) return Read(null, v.offset)
        if (v.high == self) return Read(self, 0)
        val op = v.def ?: return null
        return when (op.opcode) {
            PcodeOp.CAST, PcodeOp.COPY -> read(op.getInput(0), depth + 1)

            PcodeOp.INT_ADD, PcodeOp.PTRSUB -> sum(read(op.getInput(0), depth + 1), read(op.getInput(1), depth + 1))

            PcodeOp.PTRADD -> {
                val size = op.getInput(2).takeIf { it.isConstant }?.offset ?: return null
                val index = read(op.getInput(1), depth + 1)?.takeIf { it.root == null && it.vbtable == null }
                    ?: return null
                sum(read(op.getInput(0), depth + 1), index.copy(offset = index.offset * size))
            }

            PcodeOp.LOAD -> load(read(op.getInput(1), depth + 1) ?: return null)

            else -> null
        }
    }

    private fun sum(a: Read?, b: Read?): Read? {
        if (a == null || b == null) return null
        // The sum of two pointers, or of two vbtable addresses, doesn't point anywhere.
        if ((a.root != null && b.root != null) || (a.vbtable != null && b.vbtable != null)) return null
        return Read(a.root ?: b.root, a.offset + b.offset, a.throughVbtable || b.throughVbtable, a.vbtable ?: b.vbtable)
    }

    /** What [from] loads: the vbtable stored at `self` + pdisp, or one of that vbtable's entries after the first. */
    private fun load(from: Read): Read? = when {
        from.root == self && !from.throughVbtable && from.vbtable == null ->
            vbtables[from.offset]?.let { Read(null, 0, vbtable = it) }

        from.root == null && from.vbtable != null ->
            vbtableEntry(from.vbtable, from.offset)?.let { Read(null, it, throughVbtable = true) }

        else -> null
    }

    /**
     * The vbase offset stored [at] bytes into [vbtable], an entry after the first. A real entry is positive,
     * because a virtual base sits after the vbptr. It is also small and word-aligned, which no code address is.
     */
    private fun vbtableEntry(vbtable: Address, at: Long): Long? {
        if (at <= 0 || at > MAX_ENTRIES * 4 || at % 4 != 0L) return null
        val entry = runCatching { program.memory.getInt(vbtable.add(at)).toLong() }.getOrNull()
        return entry?.takeIf { it in 1..<MAX_VBASE_OFFSET && it % 4 == 0L }
    }

    private companion object {
        const val MAX_DEPTH = 24
        const val MAX_ENTRIES = 64
        const val MAX_VBASE_OFFSET = 0x10000L
    }
}

/**
 * The constants that this function stores into [self] at offsets read from a vbtable, mapped from each store's
 * address to the offset it stores at. This works without RTTI, which is what would otherwise say where the
 * vbptrs are.
 *
 * An MSVC constructor first stores a vbtable's address at `this + pdisp`. It then reaches a virtual base's
 * vptr as `this + *(*(this + pdisp) + vdisp) + k`, so the offset is `pdisp`'s vbtable entry at `vdisp`
 * ([vbtableEntry]) plus `k`. No Itanium vtable is read this way: its vbase offsets sit before its address
 * point, and its slots hold code.
 */
fun HighFunction.storesThroughVbtables(self: HighVariable): Map<Address, Long> {
    val program = function.program
    val vbtables = constantStores()[self].orEmpty().filterValues(program::mayBeVbtable)
    if (vbtables.isEmpty()) return emptyMap()
    return VbaseReader(program, self, vbtables).run {
        pcodeOps.asSequence()
            .filter { it.opcode == PcodeOp.STORE && it.getInput(2).isConstantPointer() }
            .mapNotNull { op ->
                read(op.getInput(1))?.takeIf { it.root == self && it.throughVbtable }?.let {
                    (op.seqnum.target to it.offset)
                }
            }.toMap()
    }
}
