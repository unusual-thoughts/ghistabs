package ghistabs.render

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.DataUtilities.ClearDataMode
import ghidra.program.model.data.TerminatedStringDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
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
 * Data a pointer targets, defining a string at [addr] when its bytes are an ASCII run
 * Ghidra's string detector recognises. Such a run is often left undefined or, worse,
 * mis-disassembled as code (`char const * align_prefix` → "#!ALIGN "); since
 * createData's ClearDataMode only clears conflicting *data*, the mis-identified code
 * units are cleared first. An already-defined string is kept as-is. Returns the resolved
 * data, else the existing data. Requires an open transaction (the render loop opens one).
 */
private fun resolvePointee(program: Program, addr: Address): Data? {
    val existing = program.listing.getDataAt(addr)
    if (existing != null && existing.isDefined && existing.value is String) return existing
    val len = asciiStringLen(program, addr) ?: return existing
    runCatching {
        program.listing.clearCodeUnits(addr, addr.add((len - 1).toLong()), false)
        DataUtilities.createData(
            program,
            addr,
            TerminatedStringDataType.dataType,
            -1, // dynamic — Ghidra sizes the terminated string itself
            ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
        )
    }.getOrNull()?.let { return it }
    return existing
}

private fun Data.repr() = runCatching { defaultValueRepresentation }.getOrNull()
    ?.takeIf { it.isNotEmpty() && it != "??" && !it.contains("Empty-Structure") }

/**
 * Render a [Data] node to one inline representation, recursing through arrays and
 * structs to any depth and chasing pointers at every leaf (defining a string at the
 * target when [resolvePointee] detects one). String-like data (char arrays, string
 * types) renders as its quoted literal rather than spreading per character; [depth]
 * guards against pointer cycles.
 */
fun Data.render(program: Program, depth: Int = 0): String? {
    if (depth > 12) return repr()
    // char array / string type — Ghidra renders the quoted literal directly.
    if (value is String) return repr()
    // pointer — chase the target, defining a string there if it's an undefined run.
    (value as? Address)?.let { ptr ->
        resolvePointee(program, ptr)?.takeIf { it.isDefined }?.let {
            return it.render(program, depth + 1) ?: repr()
        }
        return repr()
    }
    // array / struct — recurse each component into a brace-list.
    if (numComponents > 0) {
        val parts = (0 until numComponents).mapNotNull { i ->
            getComponent(i)?.render(program, depth + 1)
        }
        if (parts.isNotEmpty()) return "{ ${parts.joinToString(", ")} }"
    }
    return repr()
}

/**
 * Initializer element(s) for a global/static at [addr] via Ghidra's data API. A scalar
 * or pointer comes back as a single element; an array or multi-field struct comes back
 * as one (recursively rendered) element per component. Returns null when nothing
 * informative is found. Callers render a single element inline (`= v;`) and spread a
 * multi-element list.
 */
/**
 * The string a pointer-typed global points at when Ghidra left its slot an untyped
 * scalar (mis-disassembled data), so [initializerAt] would print the raw address. Reads
 * the stored value as an address and, if the target is an ASCII run, defines and returns
 * the quoted literal. Null when the slot isn't a scalar or the target isn't a string.
 */
fun Program.pointerString(addr: Address): String? {
    val target = (listing.getDataAt(addr)?.value as? Scalar)
        ?.let { addressFactory.defaultAddressSpace.getAddress(it.value) } ?: return null
    return resolvePointee(this, target)?.takeIf { it.isDefined && it.value is String }?.render(this)
}

/**
 * The quoted string literal a `char[N]` global holds, defining it at [addr] when Ghidra
 * left the run undefined or (RTTI typeinfo-name strings like `_ZTS8XDVImage` → "8XDVImage")
 * mis-disassembled it as code. Null when [addr]'s bytes aren't a printable run. Rendering
 * as one literal keeps the global on its own line instead of spreading a per-byte list.
 */
fun Program.stringLiteralAt(addr: Address): String? =
    resolvePointee(this, addr)?.takeIf { it.isDefined && it.value is String }?.render(this)

fun Program.initializerAt(addr: Address): List<String>? {
    val data = listing.getDataAt(addr) ?: return null
    // A real aggregate (struct / non-char array) spreads one element per component; a
    // pointer, scalar, or string-like value is a single element.
    if (data.value !is String && data.value !is Address && data.numComponents > 0) {
        val parts = (0 until data.numComponents).mapNotNull { i ->
            data.getComponent(i)?.render(this)
        }
        return parts.takeIf { it.isNotEmpty() }
    }
    return data.render(this)?.let { listOf(it) }
}
