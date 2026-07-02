package ghistabs.materialize

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.program.model.listing.Program
import ghistabs.demangle
import ghistabs.materialize.VtableSymbolCandidates.decodesToClass
import ghistabs.parse.splitQualified

/** Candidate vtable symbol names for direct lookup, plus a demangler-based recognizer for templates. */
object VtableSymbolCandidates {
    /** Closed-form `_ZTV` candidates for [className]. Templates have no closed form — use [decodesToClass]. */
    fun mangledZtvCandidates(className: String): List<String> {
        val itaniumMangled = itaniumMangleClassName(className)
        val gcc2 = $$"_vt$$${className}$"
        return listOf(
            "_ZTV$itaniumMangled", // Itanium canonical
            "__ZTV$itaniumMangled", // Cygwin/PE leading-underscore variant
            gcc2, // gcc2 fallback
            "$className::vtable", // some compilers emit this
        )
    }

    /** True if [symbolName] demangles to a vtable for [className]. Handles templated `_ZTV…` names. */
    fun decodesToClass(program: Program, symbolName: String, className: String): Boolean {
        if (!looksLikeZtv(symbolName)) return false
        val obj = demangle(program, symbolName) ?: return false
        return demangledMatchesClass(obj, className)
    }

    /** String-level pre-filter so we don't pay the demangler cost on every label. */
    internal fun looksLikeZtv(symbolName: String): Boolean = symbolName.trimStart('_').startsWith("ZTV")

    /** Pure inspection of a demangled object — extracted for unit testing without a real `Program`. */
    internal fun demangledMatchesClass(obj: ghidra.app.util.demangler.DemangledObject, className: String): Boolean {
        if (obj !is DemangledAddressTable || obj.name != "vtable") return false
        val chain = generateSequence(obj.namespace) { it.namespace }
            .map { it.name }
            .toList()
            .asReversed()
            .joinToString("::")
        return chain == className
    }

    /**
     * Itanium-mangle a nested class name. `Foo`→`3Foo`, `Foo::Bar`→`N3Foo3BarE`.
     * Templates are returned unchanged for the caller to fall back to a demangler scan.
     */
    fun itaniumMangleClassName(name: String): String {
        if ('<' in name) return name
        val parts = splitQualified(name)
        return if (parts.size == 1) {
            "${parts[0].length}${parts[0]}"
        } else {
            "N" + parts.joinToString("") { "${it.length}$it" } + "E"
        }
    }
}
