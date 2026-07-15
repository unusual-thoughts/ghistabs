package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.CharDataType
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.DataUtilities.ClearDataMode
import ghidra.program.model.data.DefaultDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.SignedByteDataType
import ghidra.program.model.data.TerminatedStringDataType
import ghidra.program.model.data.TypeDef
import ghidra.program.model.data.Undefined
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.util.ascii.AsciiCharSetRecognizer

/**
 * Length (including the terminator) of the NUL-terminated run of characters Ghidra's
 * string charset ([AsciiCharSetRecognizer], the recogniser its StringSearcher wraps)
 * accepts at [addr], or null if [addr] doesn't begin one. A point query — we already
 * hold the exact address, so there's nothing to search for.
 */
private fun asciiStringLen(program: Program, addr: Address, max: Int = 4096): Int? {
    val charSet = AsciiCharSetRecognizer()
    val bytes = ByteArray(max)
    val n = runCatching { program.memory.getBytes(addr, bytes) }.getOrNull() ?: return null
    for (i in 0 until n) {
        val b = bytes[i].toInt() and 0xff
        if (b == 0) return if (i > 0) i + 1 else null
        if (!charSet.contains(b)) return null
    }
    return null
}

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
private fun desiredPointee(program: Program, addr: Address, pointee: DataType?): Pair<DataType, Int>? = when {
    !pointee.isStringPointee() && pointee!!.length > 0 -> pointee to pointee.length
    else -> asciiStringLen(program, addr)?.let { TerminatedStringDataType.dataType to it }
}

/**
 * Whether the data already at a target is at least as precise as [desired], so the sweep
 * leaves it be. A bare Undefined/Default placeholder never counts — that's what auto-
 * analysis drops on unreferenced bytes, and we hold the better stab-derived type. A string
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
 * is overwritten. Such targets are often left undefined or, worse, mis-disassembled as code
 * (`char const * align_prefix` → "#!ALIGN "); since createData's ClearDataMode only clears
 * conflicting *data*, the mis-identified code units are cleared first. Returns the resolved
 * (or pre-existing) data, else null. Requires an open transaction (the apply/render loops
 * open one).
 */
fun resolvePointee(program: Program, addr: Address, pointee: DataType? = null): Data? {
    val existing = program.listing.getDataAt(addr)
    val (dt, len) = desiredPointee(program, addr, pointee) ?: return existing
    if (existing != null && existing.satisfiedBy(dt)) return existing
    return runCatching {
        program.listing.clearCodeUnits(addr, addr.add((len - 1).toLong()), false)
        DataUtilities.createData(program, addr, dt, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
    }.getOrNull() ?: existing
}

/**
 * Follow every pointer reachable from [data] (a just-typed global/static) and lay the
 * pointee's declared type at each target that's undefined or a mere placeholder — the
 * anonymous statics gcc emits with no stab (string literals, RTTI tables, out-of-line
 * constants). Recurses through arrays, structs and each target it (re)defines; a target
 * already carrying a precise type is left to whichever referrer first reached it. [depth]
 * guards pointer cycles. Returns the number of targets (re)defined.
 */
fun sweepPointees(program: Program, data: Data, depth: Int = 0): Int {
    if (depth > 12) return 0
    (data.value as? Address)?.let { target ->
        val before = program.listing.getDataAt(target)?.takeIf { it.isDefined }?.dataType
        val resolved = resolvePointee(program, target, (data.dataType as? Pointer)?.dataType) ?: return 0
        if (before != null && resolved.dataType.isEquivalent(before)) return 0
        return 1 + sweepPointees(program, resolved, depth + 1)
    }
    return (0 until data.numComponents).sumOf { i ->
        data.getComponent(i)?.let { sweepPointees(program, it, depth + 1) } ?: 0
    }
}
