package ghistabs.parse

/**
 * Helpers for the C++ source-form qualified names that arrive in stab records.
 *
 * gcc writes demangled names directly into stabs — e.g.
 * `std::basic_string<char, std::char_traits<char>, std::allocator<char>>` —
 * so we never get a structured tree, only a flat string with `::` separators
 * that can also appear inside template arguments. Naive splitting on `::`
 * shreds template parameters; this is the depth-aware alternative.
 *
 * For names that have a matching mangled token, prefer Ghidra's
 * `DemanglerUtil` and walk `Demangled.getNamespace()` — that path never
 * touches strings at all. This util is the fallback for type-only stabs that
 * have no mangled symbol.
 */
object QualifiedName {
    /**
     * Split a C++ qualified name on `::`, ignoring separators that appear
     * inside angle brackets or parentheses.
     *
     * `std::map<K, V>::iterator` → `["std", "map<K, V>", "iterator"]`.
     */
    fun split(name: String): List<String> {
        val parts = mutableListOf<String>()
        val cur = StringBuilder()
        var angle = 0
        var paren = 0
        var i = 0
        while (i < name.length) {
            val c = name[i]
            when {
                c == '<' -> {
                    angle++
                    cur.append(c)
                }

                c == '>' -> {
                    angle--
                    cur.append(c)
                }

                c == '(' -> {
                    paren++
                    cur.append(c)
                }

                c == ')' -> {
                    paren--
                    cur.append(c)
                }

                c == ':' &&
                    angle == 0 &&
                    paren == 0 &&
                    i + 1 < name.length &&
                    name[i + 1] == ':' -> {
                    if (cur.isNotEmpty()) {
                        parts.add(cur.toString())
                        cur.clear()
                    }
                    i++
                }

                else -> cur.append(c)
            }
            i++
        }
        if (cur.isNotEmpty()) parts.add(cur.toString())
        return parts
    }

    /**
     * Strip template arguments and namespace qualifiers from a class name.
     *
     *   `basic_istream<char,std::char_traits<char>>` → `basic_istream`
     *   `std::basic_istream`                          → `basic_istream`
     *   `__gnu_cxx::__normal_iterator<char*,…>`       → `__normal_iterator`
     *
     * Used by the XRef base-tag fallback to bridge "forward-declared bare tag in one
     * CU vs full template instantiation in another" — the cross-CU mismatch is
     * structural in gcc stabs, not a libstdc++-version detail, so this helper has no
     * hardcoded names.
     */
    fun baseTag(name: String): String {
        val noArgs = name.indexOf('<').let { if (it >= 0) name.substring(0, it) else name }
        return noArgs.trim().substringAfterLast("::")
    }
}
