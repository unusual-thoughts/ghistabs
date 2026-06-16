package ghistabs.materialize

import ghidra.app.util.demangler.DemangledAddressTable
import ghidra.app.util.demangler.DemanglerUtil
import ghidra.program.model.listing.Program
import ghistabs.materialize.VtableSymbolCandidates.decodesToClass

object VtableSymbolCandidates {
    /**
     * Ordered candidate symbol names that may resolve to a vtable for
     * [className] via direct lookup (`resolver.resolve(name)`). For
     * templated class names there is no closed-form mangling, so the
     * caller must fall back to a symbol-table scan with
     * [decodesToClass] (which round-trips through the real demangler).
     */
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

    /**
     * True if [symbolName] is a vtable symbol whose demangled class chain
     * matches [className]. Built on Ghidra's `GnuDemangler` so templated
     * vtables (e.g. `_ZTVN3std6vectorIiSaIiEEE`) are recognised — the
     * old reverse-mangling path punted on `<` and missed those.
     */
    fun decodesToClass(program: Program, symbolName: String, className: String): Boolean {
        if (!looksLikeZtv(symbolName)) return false
        val obj = runCatching {
            DemanglerUtil.demangle(program, symbolName, null).firstOrNull()
        }.getOrNull() ?: return false
        return demangledMatchesClass(obj, className)
    }

    /** String-level pre-filter so we don't pay the demangler cost on every label. */
    internal fun looksLikeZtv(symbolName: String): Boolean = symbolName.trimStart('_').startsWith("ZTV")

    /**
     * Inspect a [DemangledObject] (typically from `_ZTV…`) and report whether
     * it's a vtable for [className]. Pure — extracted so unit tests can
     * exercise it with a synthetic `DemangledAddressTable` and avoid the
     * Ghidra demangler's `Program`-dependent setup path.
     */
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
     * Itanium-mangle a (possibly nested) class name. Templated names not supported —
     * caller falls back to [decodesToClass]-based symbol-table scan.
     * Examples:
     *   "Foo" → "3Foo"
     *   "Foo::Bar" → "N3Foo3BarE"
     *   "vector<int>" → "vector<int>" (templated, punted to caller)
     */
    fun itaniumMangleClassName(name: String): String {
        if ('<' in name) return name // templated → caller falls back
        val parts = QualifiedName.split(name)
        return if (parts.size == 1) {
            "${parts[0].length}${parts[0]}"
        } else {
            "N" + parts.joinToString("") { "${it.length}$it" } + "E"
        }
    }
}
