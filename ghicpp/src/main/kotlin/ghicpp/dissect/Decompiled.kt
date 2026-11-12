package ghicpp.dissect

import ghicpp.ClassDecl
import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighVariable
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghidrakt.useWith

/** How long a class pass waits on the decompiler for one function. */
const val DECOMPILE_TIMEOUT_SECONDS = 30

/**
 * Decompiles each of [funcs] in turn, under one decompiler, and hands [block] what it made of each, until [monitor]
 * is cancelled, reporting progress under [message]. A function that doesn't decompile goes to [undecompiled].
 */
fun Program.decompileEach(
    funcs: Collection<Function>,
    monitor: TaskMonitor,
    message: String,
    undecompiled: (Function) -> Unit = {},
    block: (Function, HighFunction) -> Unit,
) {
    monitor.initialize(funcs.size.toLong(), message)
    DecompInterface().useWith(this) { decomp ->
        for (func in funcs) {
            if (monitor.isCancelled) break
            monitor.incrementProgress()
            val high = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
            if (high == null) undecompiled(func) else block(func, high)
        }
    }
}

/** Each of these classes' vtables, by its address point: the class it serves and where its vptr sits in it. */
fun Collection<ClassDecl>.vptrTables(program: Program): Map<Address, Pair<ClassDecl, Long>> = flatMap { cls ->
    cls.vftables.mapNotNull { r -> r.vfptrOffset(program)?.let { r.addressPoint to (cls to it) } }
}.toMap()

/**
 * The functions whose code refers to one of [tables] ([vptrTables]), which store vptrs: by function, each
 * instruction referring to one, and what the tables it refers to serve.
 */
fun Program.vptrWriters(
    tables: Map<Address, Pair<ClassDecl, Long>>,
): Map<Function, Map<Address, List<Pair<ClassDecl, Long>>>> =
    buildMap<Function, MutableMap<Address, MutableList<Pair<ClassDecl, Long>>>> {
        for ((table, served) in tables) {
            for (ref in referenceManager.getReferencesTo(table)) {
                val at = ref.fromAddress
                if (listing.getInstructionAt(at) == null) continue
                val func = functionManager.getFunctionContaining(at) ?: continue
                getOrPut(func) { mutableMapOf() }.getOrPut(at) { mutableListOf() } += served
            }
        }
    }

/**
 * The addresses this function stores as constants into each object, by the variable the object is
 * ([PointerInto.root]) and the offset into it: the vptrs and vbtables a constructor stores, among others.
 */
fun HighFunction.constantStores(): Map<HighVariable, Map<Long, Address>> {
    val stores = mutableMapOf<HighVariable, MutableMap<Long, Address>>()
    for (op in pcodeOps) {
        if (op.opcode != PcodeOp.STORE) continue
        val value = op.getInput(2).constant()?.let { function.program.addressIn(it) } ?: continue
        val (root, offset) = op.getInput(1).pointerInto() ?: continue
        stores.getOrPut(root) { mutableMapOf() }[offset] = value
    }
    return stores
}

/** The constant [this] is, the decompiler's `&DAT_…` (`PTRSUB 0, addr`) included. */
private fun Varnode.constant(): Long? = when {
    isConstant -> offset

    def?.opcode == PcodeOp.PTRSUB && def.getInput(0).let { it.isConstant && it.offset == 0L } ->
        def.getInput(1).takeIf { it.isConstant }?.offset

    def?.opcode == PcodeOp.COPY -> def.getInput(0).takeIf { it.isConstant }?.offset

    else -> null
}

/** [value] as an address in the default space, where it is in memory. */
private fun Program.addressIn(value: Long) =
    runCatching { addressFactory.defaultAddressSpace.getAddress(value) }.getOrNull()?.takeIf(memory::contains)

/**
 * A pointer as the variable it points into ([root]) and how far past it ([offset]). The decompiler merges a
 * variable's copies and phis into one [HighVariable], so [root] is the same however the pointer got there.
 */
data class PointerInto(val root: HighVariable, val offset: Long) {
    /** Whether [root] is the function's incoming `this`, which comes in at [thisStorage]. */
    fun isThis(thisStorage: Address?) = root.instances.any { it.isInput && it.address == thisStorage }
}

/** Traces a decompiled pointer back through casts and constant adds to the variable it points into. */
fun Varnode.pointerInto(offset: Long = 0, depth: Int = 0): PointerInto? = when (
    (def?.opcode)?.takeIf { depth < MAX_TRACE }
) {
    PcodeOp.CAST -> def.getInput(0).pointerInto(offset, depth + 1)

    PcodeOp.INT_ADD, PcodeOp.PTRSUB -> def.getInput(1).takeIf { it.isConstant }?.let { by ->
        def.getInput(0).pointerInto(offset + by.offset, depth + 1)
    }

    PcodeOp.PTRADD -> {
        val (index, size) = def.getInput(1) to def.getInput(2)
        when {
            !index.isConstant || !size.isConstant -> null
            else -> def.getInput(0).pointerInto(offset + index.offset * size.offset, depth + 1)
        }
    }

    else -> null
} ?: high?.let { PointerInto(it, offset) }

private const val MAX_TRACE = 16

/** The class a function storing [classes]' vtables builds or destroys: the one the others are bases of, or null. */
fun storedClass(classes: Set<ClassDecl>): ClassDecl? =
    classes.singleOrNull { c -> classes.all { it == c || c.derivesFrom(it) } }
