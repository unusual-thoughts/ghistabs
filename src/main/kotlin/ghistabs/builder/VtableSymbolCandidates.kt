package ghistabs.builder

object VtableSymbolCandidates {
    /**
     * Ordered candidate symbol names that may resolve to a vtable for [className].
     * Tries Itanium mangling first, then Cygwin/PE variants, then gcc2 fallback.
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
     * True if [symbolName] (with any leading underscore stripped) decodes
     * to the Itanium-mangled form of [className]. Used by the symbol-iterator fallback.
     */
    fun itaniumDecodesToClass(symbolName: String, className: String): Boolean {
        // Strip all leading underscores (handle both _ZTV and __ZTV variants)
        var stripped = symbolName
        while (stripped.startsWith("_")) {
            stripped = stripped.drop(1)
        }
        if (!stripped.startsWith("ZTV")) return false
        val rest = stripped.removePrefix("ZTV")
        return rest == itaniumMangleClassName(className)
    }

    /**
     * Itanium-mangle a (possibly nested) class name. Templated names not supported.
     * Examples:
     *   "Foo" → "3Foo"
     *   "Foo::Bar" → "N3Foo3BarE"
     *   "vector<int>" → "vector<int>" (templated, punted to caller)
     */
    fun itaniumMangleClassName(name: String): String {
        if ('<' in name) return name // templated → caller falls back
        val parts = name.split("::").filter { it.isNotEmpty() }
        return if (parts.size == 1) {
            "${parts[0].length}${parts[0]}"
        } else {
            "N" + parts.joinToString("") { "${it.length}$it" } + "E"
        }
    }
}
