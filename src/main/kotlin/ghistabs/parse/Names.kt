package ghistabs.parse

/**
 * Pure C++ name-string operations for stabs (gcc writes names demangled) — no Ghidra dependency.
 * Source-form namespace/template splitting, template-whitespace canonicalisation, and Itanium
 * mangled-name classification. Ghidra's demangler proper lives in `ghistabs.Demangler`; prefer it
 * when a mangled token is available, these are the string-only fallbacks and predicates.
 */

/**
 * gcc's vtable-pointer member: `_vptr$<Class>` through gcc 4.x, `_vptr.<Class>` from gcc 12, bare
 * `_vptr` in between. The name is the only signal — the type it carries (`__vtbl_ptr_type *`) is
 * one CU-shared node reused by every polymorphic record, so it identifies nothing.
 */
fun isVptrFieldName(name: String) = name.startsWith("_vptr$") || name.startsWith("_vptr.") || name == "_vptr"

/** Split a source-form qualified name on `::`, ignoring separators inside `<>` or `()`. */
fun splitQualified(name: String): List<String> {
    val parts = mutableListOf<String>()
    val cur = StringBuilder()
    var angle = 0
    var paren = 0
    var i = 0
    while (i < name.length) {
        when (val c = name[i]) {
            '<' -> {
                angle++
                cur.append(c)
            }
            '>' -> {
                angle--
                cur.append(c)
            }
            '(' -> {
                paren++
                cur.append(c)
            }
            ')' -> {
                paren--
                cur.append(c)
            }
            ':' if angle == 0 && paren == 0 && name.getOrNull(i + 1) == ':' -> {
                if (cur.isNotEmpty()) parts.add(cur.toString().also { cur.clear() })
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
 * Strip template args + namespace: `std::basic_istream<...>` → `basic_istream`. Used by the XRef
 * base-tag fallback to bridge bare-forward-decl vs template-instantiation.
 */
fun baseTag(name: String): String = name.substringBefore('<').trim().substringAfterLast("::")

/** Whitespace around template punctuation — gcc is inconsistent (`< `, `, `, ` >`, `> >`). */
private val TEMPLATE_PUNCT = Regex("""\s*([<>,])\s*""")

/**
 * Canonical spelling of a templated name: no whitespace around `<`, `>`, `,` (multi-word types
 * like `short unsigned int` keep their spaces).
 */
fun canonTemplateName(name: String): String = TEMPLATE_PUNCT.replace(name.trim()) { it.groupValues[1] }
