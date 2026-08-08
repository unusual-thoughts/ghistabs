package ghistabs.render

/**
 * A name's every `~` that sits *inside* it, respelled `dtor_`. A name opening with one is a real
 * destructor (`~string`) and keeps it; one in the middle is Ghidra having named a vtable pointer
 * after the destructor it holds, and `~` is not an identifier character there.
 */
fun String.respellTilde() = buildString {
    this@respellTilde.forEachIndexed { i, c ->
        val inside = c == '~' &&
            i > 0 &&
            this@respellTilde[i - 1].isIdentifierChar() &&
            this@respellTilde.getOrNull(i + 1)?.let { it.isLetter() || it == '_' } == true
        if (inside) append("dtor_") else append(c)
    }
}

fun Char.isIdentifierChar() = isLetterOrDigit() || this == '_'

private val NON_IDENTIFIER = Regex("[^A-Za-z0-9]+")
fun String.sanitizeIdentifier() = replace(NON_IDENTIFIER, "_")

/**
 * `template<> ` in front of a declaration whose subject [name] carries template arguments, because
 * that is what such a declaration is: `class fpos<int> { … };` is not legal C++, `template<> class
 * fpos<int> { … };` is. gcc's stabs describe instantiations and never the primary template, so every
 * templated name the render declares is a specialisation.
 *
 * This does not make the render compile — the primary template is still nowhere, so clang moves from
 * "expected unqualified-id" to "explicit specialization of undeclared template class", which is the
 * missing-declaration family a per-file view cannot escape. It is the correct spelling of what the
 * stabs actually say, not a way to quiet the checker.
 */
fun String.asSpecialization(name: String?) =
    if (name != null && '<' in name && !name.startsWith("operator")) "template<> $this" else this

// The unqualified spelling of a type name, which is what its constructor and destructor are called:
// `std::vector<int>::vector`, not `std::vector<int>::std::vector<int>`.
fun String.simpleTypeName() = substringBefore('<').substringAfterLast("::")

fun safeName(source: String) = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").trim('_')

/**
 * C is declarator-based: an array's extent goes *after* the  * name, so `char const[18] ABC`
 * has to be `char const ABC[18]`.
 */
private val ARRAY_SUFFIX = Regex("""((?:\[[^\]]*\])+)$""")

fun declarator(type: String, name: String) = ARRAY_SUFFIX.find(type)
    ?.let { "${type.removeSuffix(it.value).trimEnd()} $name${it.value}" }
    ?: "$type $name"
