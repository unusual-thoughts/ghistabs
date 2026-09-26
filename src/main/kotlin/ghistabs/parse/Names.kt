package ghistabs.parse

// Pure C++ name-string operations for stabs (gcc writes names demangled) — no Ghidra dependency.
// Source-form namespace/template splitting, template-whitespace canonicalisation, and Itanium
// mangled-name classification. Ghidra's demangler proper lives in `ghistabs.Demangler`; prefer it
// when a mangled token is available, these are the string-only fallbacks and predicates.

/**
 * gcc's vtable-pointer member: `_vptr$<Class>` through gcc 4.x, `_vptr.<Class>` from gcc 12, bare
 * `_vptr` in between. The name is the only signal — the type it carries (`__vtbl_ptr_type *`) is
 * one CU-shared node reused by every polymorphic record, so it identifies nothing.
 */
fun isVptrFieldName(name: String) = name.startsWith("_vptr$") || name.startsWith("_vptr.") || name == "_vptr"

/**
 * A source-form qualified name split on `::`, except inside `<>` or `()`:
 * `std::map<int, A::B>::iterator` → `[std, map<int, A::B>, iterator]`. Empty segments drop.
 */
val String.nameSegments: List<String> get() = runningFold(0) { d, c ->
    d + when (c) {
        '<', '(' -> 1
        '>', ')' -> -1
        else -> 0
    }
}.withIndex().filter { (i, d) -> d == 0 && startsWith("::", i) }.map { it.index }.let { cuts ->
    (listOf(-2) + cuts).zip(cuts + length) { from, to -> substring(from + 2, to) }.filter { it.isNotEmpty() }
}

/** [nameSegments]' inverse: `[std, vector<int>]` → `std::vector<int>`. */
val List<String>.qualifiedName get() = joinToString("::")

/** A member of this scope: `A<int>` and `f` → `A<int>::f`. */
fun String.member(name: String) = "$this::$name"

/** Everything but the leaf, or null for an unqualified name: `A<int>::Inner` → `A<int>`. */
val String.enclosingName get() = nameSegments.dropLast(1).ifEmpty { null }?.qualifiedName

/** The last segment, template arguments kept: `Foo<ns::Bar>`, where a plain `::` cut gives `Bar>`. */
val String.leafName get() = nameSegments.lastOrNull() ?: this

/** Where a segment's template argument list opens; an `operator<` has none. */
private val String.argsStart get() = takeUnless { it.startsWith("operator") }?.indexOf('<')?.takeIf { it >= 0 }

/** Template arguments on any segment: `vector<int>`, `A<int>::Inner`, but not `operator<`. */
val String.isTemplated get() = nameSegments.any { it.argsStart != null }

/** Every segment's arguments dropped: `A<int>::Inner` → `A::Inner`. The template an instantiation spells. */
val String.templateName get() =
    nameSegments.map { seg -> seg.argsStart?.let { seg.take(it).trim() } ?: seg }.qualifiedName

/** [templateName]'s leaf: `std::vector<int>::iterator` → `iterator`, `std::vector<int>` → `vector`. */
val String.templateLeaf get() = leafName.templateName

/**
 * The outermost template a name sits in: `std::vector<int>::iterator` → `std::vector`. A nested class
 * is declared inside its template, so this is what shares a header; [templateName] is not.
 */
val String.outermostTemplate: String get() = nameSegments.let { segments ->
    val first = segments.indexOfFirst { it.argsStart != null }.takeIf { it >= 0 } ?: segments.lastIndex
    segments.take(first + 1).qualifiedName.templateName
}

/** Whitespace around template punctuation — gcc is inconsistent (`< `, `, `, ` >`, `> >`). */
private val TEMPLATE_PUNCT = Regex("""\s*([<>,])\s*""")

/**
 * Canonical spelling of a templated name: no whitespace around `<`, `>`, `,` (multi-word types
 * like `short unsigned int` keep their spaces).
 */
fun canonTemplateName(name: String): String = TEMPLATE_PUNCT.replace(name.trim()) { it.groupValues[1] }
