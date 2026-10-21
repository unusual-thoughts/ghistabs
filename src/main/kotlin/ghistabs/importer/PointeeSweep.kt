package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghistabs.cStringAt
import ghistabs.forceCreateData

/** Longest string a pointee is chased into, terminator included. */
private const val MAX_POINTEE_STRING = 4096

/**
 * A pointee to chase into a string rather than lay verbatim: a `char*`/`byte*` target is
 * the whole NUL-run, not one character, and a shapeless `void*`/undefined pointer (gcc's
 * unbound ids) has no type to apply — its object can only be guessed from the bytes. A
 * null pointee (bare-address caller) is treated the same.
 */
private fun DataType?.isStringPointee(): Boolean {
    val base = (this as? TypeDef)?.baseDataType ?: this ?: return true
    return base is VoidDataType ||
        base is DefaultDataType ||
        base is CharDataType ||
        base is ByteDataType ||
        base is SignedByteDataType ||
        Undefined.isUndefined(base)
}

/** The type (and byte length to clear) to lay for a pointer whose pointee is [pointee]. */
private fun Program.desiredPointee(addr: Address, pointee: DataType?): Pair<DataType, Int>? = when {
    !pointee.isStringPointee() && pointee!!.length > 0 -> pointee to pointee.length

    // A non-empty ASCII run, the charset Ghidra's StringSearcher accepts, with its NUL
    else -> cStringAt(addr, 1..<MAX_POINTEE_STRING)?.let { TerminatedStringDataType.dataType to it.length + 1 }
}

/**
 * Whether the data already at a target is at least as precise as [desired], so the sweep
 * leaves it be. A bare Undefined/Default placeholder never counts — that's what auto-analysis
 * drops on unreferenced bytes, and we hold the better stab-derived type. A string
 * target is satisfied only by an actual string, not the `undefined4` Ghidra may have guessed.
 */
private fun Data.satisfiedBy(desired: DataType): Boolean = when {
    !isDefined || Undefined.isUndefined(dataType) || dataType is DefaultDataType -> false
    desired is TerminatedStringDataType -> value is String
    else -> true
}

/**
 * Define data at [addr], the target of a pointer whose declared pointee is [pointee]: a
 * concrete sized type is laid verbatim; a char/byte/void/undefined pointee (or none) falls
 * back to a terminated string when the bytes are an ASCII run Ghidra recognises. A target
 * already carrying an at-least-as-precise type ([satisfiedBy]) is kept; a mere placeholder
 * is overwritten. Such targets are often mis-disassembled as code (`char const * align_prefix` →
 * "#!ALIGN "), hence [forceCreateData]. Returns the resolved (or pre-existing) data, else null.
 * Requires an open transaction (the apply/render loops open one).
 */
fun Program.resolvePointee(addr: Address, pointee: DataType? = null): Data? {
    val existing = listing.getDataAt(addr)
    val (dt, len) = desiredPointee(addr, pointee) ?: return existing
    if (existing != null && existing.satisfiedBy(dt)) return existing
    return runCatching { forceCreateData(addr, dt, len) }.getOrNull() ?: existing
}

/**
 * Follow every pointer reachable from [data] (a just-typed global/static) and lay the
 * pointee's declared type at each target that's undefined or a mere placeholder — the
 * anonymous statics gcc emits with no stab (string literals, RTTI tables, out-of-line
 * constants). Recurses through arrays, structs and each target it (re)defines; a target
 * already carrying a precise type is left to whichever referrer first reached it. [depth]
 * guards pointer cycles. Returns the number of targets (re)defined.
 */
fun Program.sweepPointees(data: Data, depth: Int = 0): Int {
    if (depth > 12) return 0
    (data.value as? Address)?.let { target ->
        val before = listing.getDataAt(target)?.takeIf { it.isDefined }?.dataType
        val resolved = resolvePointee(target, (data.dataType as? Pointer)?.dataType) ?: return 0
        if (before != null && resolved.dataType.isEquivalent(before)) return 0
        return 1 + sweepPointees(resolved, depth + 1)
    }
    return (0 until data.numComponents).sumOf { i ->
        data.getComponent(i)?.let { sweepPointees(it, depth + 1) } ?: 0
    }
}
