package ghistabs.parse

/**
 * Depth-aware splitting/stripping for C++ source-form names in stabs (gcc writes them demangled).
 * Prefer Ghidra's [ghidra.app.util.demangler.DemanglerUtil] when a mangled token is available;
 * this is the fallback for type-only stabs.
 */
object QualifiedName {
    /** Split on `::` ignoring separators inside `<>` or `()`. */
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
     * Strip template args + namespace. `std::basic_istream<...>` → `basic_istream`.
     * Used by the XRef base-tag fallback to bridge bare-forward-decl vs template-instantiation.
     */
    fun baseTag(name: String): String {
        val noArgs = name.indexOf('<').let { if (it >= 0) name.substring(0, it) else name }
        return noArgs.trim().substringAfterLast("::")
    }
}
