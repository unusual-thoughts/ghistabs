package ghistabs.render

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghistabs.importer.resolvePointee

fun Address.hexLiteral() = "0x" + offset.toString(16).padStart(8, '0')

private fun Data.repr() = runCatching { defaultValueRepresentation }.getOrNull()
    ?.takeIf { it.isNotEmpty() && it != "??" && !it.contains("Empty-Structure") }
    ?.let(::cStyleNumber)

// Ghidra prints scalars in its listing format — hex with a trailing `h`, all-zero runs padded.
// Rewrite to C: `DEADCAFEh` → `0xDEADCAFE`, `0h`/`00000000` → `0`. Quoted strings, enum names and
// decimals don't match, so they pass through untouched.
internal fun cStyleNumber(s: String) = when {
    s.matches(Regex("[0-9A-Fa-f]+h")) ->
        s.dropLast(1).trimStart('0').ifEmpty { "0" }.let { if (it == "0") "0" else "0x$it" }

    s.isNotEmpty() && s.all { it == '0' } -> "0"

    else -> s
}

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
    // Ghidra's own representation of a pointer is the bare address — `0040fbc0` — which C reads as an
    // octal constant, and rejects outright once a digit is 8 or 9. Spell it as hex from the Address
    // rather than pattern-matching the rendered text, which cannot tell an address from a decimal.
    (value as? Address)?.let { ptr ->
        program.resolvePointee(ptr)?.takeIf { it.isDefined }?.let {
            return it.render(program, depth + 1) ?: ptr.hexLiteral()
        }
        return ptr.hexLiteral()
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
 *
 * The string a pointer-typed global points at when Ghidra left its slot an untyped
 * scalar (mis-disassembled data), so [initializerAt] would print the raw address. Reads
 * the stored value as an address and, if the target is an ASCII run, defines and returns
 * the quoted literal. Null when the slot isn't a scalar or the target isn't a string.
 */
fun Program.pointerString(addr: Address): String? {
    val target = (listing.getDataAt(addr)?.value as? Scalar)
        ?.let { addressFactory.defaultAddressSpace.getAddress(it.value) } ?: return null
    return resolvePointee(target)?.takeIf { it.isDefined && it.value is String }?.render(this)
}

/**
 * The quoted string literal a `char[N]` global holds, defining it at [addr] when Ghidra
 * left the run undefined or (RTTI typeinfo-name strings like `_ZTS8XDVImage` → "8XDVImage")
 * mis-disassembled it as code. Null when [addr]'s bytes aren't a printable run. Rendering
 * as one literal keeps the global on its own line instead of spreading a per-byte list.
 */
fun Program.stringLiteralAt(addr: Address): String? =
    resolvePointee(addr)?.takeIf { it.isDefined && it.value is String }?.render(this)

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
