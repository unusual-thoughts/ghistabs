package ghistabs.parse

/**
 * Pure C++ name-string operations for stabs (gcc writes names demangled) — no Ghidra dependency.
 * Source-form namespace/template splitting, template-whitespace canonicalisation, and Itanium
 * mangled-name classification. Ghidra's demangler proper lives in `ghistabs.Demangler`; prefer it
 * when a mangled token is available, these are the string-only fallbacks and predicates.
 */

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

/**
 * Itanium-mangled `_ZN…` whose first scope is `std::`, `__gnu_cxx::`, or an STL shortcut
 * (`Ss`/`Sa`/`Si`/`So`/`Sd`/`St`). gcc declares these in stabs even when COMDAT-dropped, so a
 * missing Function at the asserted address is expected — routed to `*-inlined-std`.
 */
private val INLINE_STD_MEMBER = Regex("""^_ZN[KV]*(?:S[adios]|St|9__gnu_cxx)""")

fun isInlineStdMember(name: String): Boolean = INLINE_STD_MEMBER.containsMatchIn(name)

/**
 * A gcc implicit trivial special member by its Itanium tail: `C[123]`=ctor (in-charge/not-in-charge/
 * allocating), `D[012]`=dtor (deleting/in-charge/not-in-charge), `aS`=operator=; `E` closes the
 * nested-name; the arg list is `v`=(), `RKS_`=(const Self&) or `OS_`=(Self&&).
 */
private val IMPLICIT_SPECIAL_MEMBER_TAIL = Regex("""(?:C[123]|D[012]|aS)E(?:v|RKS_|OS_)$""")

fun isImplicitTrivialSpecialMember(mangled: String): Boolean =
    mangled.startsWith("_ZN") && IMPLICIT_SPECIAL_MEMBER_TAIL.containsMatchIn(mangled)

/**
 * Outermost class/namespace name from an Itanium nested-name mangle: `_ZN13EquExpressionC1ERKS_` →
 * `EquExpression`, `_ZN7CParser11ParseSymbolEv` → `CParser`. Reads the first length-prefixed segment.
 * Null for a non-nested mangle (`_Z…` without `N`) or a substitution-prefix first segment (`St`=std,
 * etc.) — callers want those to keep their N_SLINE attribution rather than be pinned to a class.
 */
fun outermostClassOf(mangled: String): String? {
    if (!mangled.startsWith("_ZN")) return null
    val start = 3
    if (start >= mangled.length || !mangled[start].isDigit()) return null
    var j = start
    while (j < mangled.length && mangled[j].isDigit()) j++
    val len = mangled.substring(start, j).toIntOrNull() ?: return null
    return if (j + len <= mangled.length) mangled.substring(j, j + len) else null
}
