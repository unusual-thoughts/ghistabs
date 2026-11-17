package ghicpp.abi.msvc

import ghicpp.ClassDecl
import ghicpp.dissect.*
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

/**
 * Finds MSVC vbtables, which no RTTI points at: a function building a class, its constructor or one it
 * was inlined into, stores the class's vftables and vbtables into the object, so the address stored where
 * a vbptr sits, in an object [classes]' vftables say is of that class, is that class's vbtable there. It reads
 * the functions a [ThisFunctionDissector] decompiles for their vptr stores ([add]).
 */
class VbtableFinder(
    private val program: Program,
    classes: Collection<ClassDecl>,
    /** Where each class with virtual bases has its vbptrs. */
    private val vbptrs: Map<ClassDecl, Set<Long>>,
) {
    private val tables = classes.vptrTables(program)

    /** Each of [vbptrs]' classes' vbtables, by where its vbptr sits in the class, where a function stores one. */
    val found: Map<ClassDecl, Map<Long, Address>> get() = vbtables

    private val vbtables = mutableMapOf<ClassDecl, MutableMap<Long, Address>>()

    /** Adds the vbtables [high] stores where [vbptrs] says its objects' classes have vbptrs. */
    fun add(high: HighFunction) {
        for ((cls, stored) in high.objectsBuilt()) {
            for (at in vbptrs[cls].orEmpty()) {
                val vbtable = stored[at]?.takeIf(::mayBeVbtable) ?: continue
                vbtables.getOrPut(cls) { mutableMapOf() }.putIfAbsent(at, vbtable)
            }
        }
    }

    /**
     * Each object this function stores a vftable into where it belongs, by the class the vftables say it
     * is ([storedClass]), with the address it stores at each offset into it ([constantStores]).
     */
    private fun HighFunction.objectsBuilt(): Map<ClassDecl, Map<Long, Address>> {
        val objects = constantStores().toMutableMap()
        // A virtual base's vptr goes where the vbtable stored beside it puts the base: into that object.
        for (root in objects.keys.toList()) {
            val (into, at) = root.throughVbtable(objects) ?: continue
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
    private fun HighVariable.throughVbtable(stores: Map<HighVariable, Map<Long, Address>>): PointerInto? {
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
                ?.takeIf(::mayBeVbtable)
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

    private fun mayBeVbtable(at: Address) = program.mayBeVbtable(at)

    companion object {
        /**
         * The constants that [high] stores into [self] at offsets read from a vbtable, mapped from each store's
         * address to the offset it stores at. This works without RTTI, which is what would otherwise say where the
         * vbptrs are.
         *
         * An MSVC constructor first stores a vbtable's address at `this + pdisp`. It then reaches a virtual base's
         * vptr as `this + *(*(this + pdisp) + vdisp) + k`, so the offset is `pdisp`'s vbtable entry at `vdisp`
         * ([vbtableEntry]) plus `k`. No Itanium vtable is read this way: its vbase offsets sit before its address
         * point, and its slots hold code.
         */
        fun storesThroughVbtables(high: HighFunction, self: HighVariable): Map<Address, Long> {
            val program = high.function.program
            val vbtables = high.constantStores()[self].orEmpty().filterValues(program::mayBeVbtable)
            if (vbtables.isEmpty()) return emptyMap()
            val reader = VbaseReader(program, self, vbtables)
            return high.pcodeOps.asSequence().filter {
                it.opcode == PcodeOp.STORE && it.getInput(2).isConstantPointer()
            }
                .mapNotNull { op ->
                    val v = reader.read(op.getInput(1)) ?: return@mapNotNull null
                    (op.seqnum.target to v.offset).takeIf { v.root == self && v.throughVbtable }
                }.toMap()
        }

        private fun Varnode.isConstantPointer(): Boolean = isConstant ||
            def?.let { it.opcode == PcodeOp.PTRSUB || it.opcode == PcodeOp.COPY || it.opcode == PcodeOp.CAST } == true
    }
}

/**
 * Whether [at] may be a vbtable. Its first entry is the offset from the vbptr back to the start of its subobject,
 * so it can't be positive.
 */
private fun Program.mayBeVbtable(at: Address) = runCatching { memory.getInt(at) <= 0 }.getOrDefault(false)

/**
 * A value as [VbaseReader] reads it: [root] plus [offset], or just the constant [offset] when [root] is null.
 * [vbtable] means the value is the address of a vbtable that `self` holds. [throughVbtable] means a vbtable entry
 * was added into it.
 */
private data class Read(val root: HighVariable?, val offset: Long, val throughVbtable: Boolean, val vbtable: Boolean)

/**
 * Reads a pointer's value as the variable it points into plus a constant offset. [vbtables] holds the vbtables
 * the function stored into [self], by offset. Loading one back gives that vbtable's address, and loading an
 * entry from it gives the entry's value.
 */
private class VbaseReader(
    private val program: Program,
    private val self: HighVariable,
    private val vbtables: Map<Long, Address>,
) {
    fun read(v: Varnode, depth: Int = 0): Read? {
        if (depth > MAX_DEPTH) return null
        if (v.isConstant) return Read(null, v.offset, throughVbtable = false, vbtable = false)
        if (v.high == self) return Read(self, 0, throughVbtable = false, vbtable = false)
        val op = v.def ?: return null
        return when (op.opcode) {
            PcodeOp.CAST, PcodeOp.COPY -> read(op.getInput(0), depth + 1)

            PcodeOp.INT_ADD, PcodeOp.PTRSUB -> sum(read(op.getInput(0), depth + 1), read(op.getInput(1), depth + 1))

            PcodeOp.PTRADD -> {
                val size = op.getInput(2).takeIf { it.isConstant }?.offset ?: return null
                val index = read(op.getInput(1), depth + 1)?.takeIf { it.root == null && !it.vbtable } ?: return null
                sum(read(op.getInput(0), depth + 1), index.copy(offset = index.offset * size))
            }

            PcodeOp.LOAD -> load(read(op.getInput(1), depth + 1) ?: return null)

            else -> null
        }
    }

    private fun sum(a: Read?, b: Read?): Read? {
        if (a == null || b == null) return null
        // The sum of two pointers, or of two vbtable addresses, doesn't point anywhere.
        if ((a.root != null && b.root != null) || (a.vbtable && b.vbtable)) return null
        return Read(a.root ?: b.root, a.offset + b.offset, a.throughVbtable || b.throughVbtable, a.vbtable || b.vbtable)
    }

    /** What [from] loads: the vbtable stored at `self` + pdisp, or one of that vbtable's entries after the first. */
    private fun load(from: Read): Read? = when {
        from.root == self && !from.throughVbtable -> vbtables[from.offset]?.let {
            Read(null, it.offset, throughVbtable = false, vbtable = true)
        }

        from.root == null && from.vbtable -> vbtableEntry(from.offset)?.let {
            Read(null, it, throughVbtable = true, vbtable = false)
        }

        else -> null
    }

    /**
     * The vbase offset stored at [at], an entry after the first in one of [vbtables]. A real entry is positive,
     * because a virtual base sits after the vbptr. It is also small, word-aligned, and not a code address. Returns
     * null when [at] is further into the vbtable than any vbtable's entries reach.
     */
    private fun vbtableEntry(at: Long): Long? {
        val table = vbtables.values.filter { it.offset < at && at - it.offset <= MAX_ENTRIES * 4 }
            .maxByOrNull { it.offset } ?: return null
        if ((at - table.offset) % 4 != 0L) return null
        val entry = runCatching { program.memory.getInt(table.add(at - table.offset)).toLong() }.getOrNull()
        return entry?.takeIf { it > 0 && it < MAX_VBASE_OFFSET && it % 4 == 0L && !isCode(it) }
    }

    /** Whether [value] is the address of code. A vtable's slot holds one, but a vbtable's entry never does. */
    private fun isCode(value: Long) = runCatching { program.addressFactory.defaultAddressSpace.getAddress(value) }
        .getOrNull()?.let { program.memory.getBlock(it)?.isExecute } == true

    private companion object {
        const val MAX_DEPTH = 24
        const val MAX_ENTRIES = 64
        const val MAX_VBASE_OFFSET = 0x10000L
    }
}
