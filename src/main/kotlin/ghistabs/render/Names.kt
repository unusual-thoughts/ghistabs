package ghistabs.render

import ghistabs.harvest.GhidraSourceFile
import ghistabs.harvest.rootSegment
import ghistabs.harvest.segments
import ghistabs.parse.isDriveLetter
import kotlin.io.path.Path

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

private val NON_IDENTIFIER_CHAR = Regex("[^A-Za-z0-9_]+")

/**
 * A C++ name as an identifier, underscores intact — for a name read off real source, where they
 * carry meaning: [sanitizeIdentifier] collapses runs, and every reserved libstdc++ name opens with
 * `__`, so `__destroy_aux` would come out `_destroy_aux` and not be findable in the header it names.
 * A leading `~` becomes `dtor_`, the spelling [respellTilde] already uses.
 */
fun String.asIdentifier() = (if (startsWith("~")) "dtor_" + drop(1) else this).replace(NON_IDENTIFIER_CHAR, "_")

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

private val GhidraSourceFile.sanitizedRoot get() =
    rootSegment?.let { if (it.isDriveLetter) it.removeSuffix(":") else it }
private val GhidraSourceFile.sanitizedSegments get() =
    sanitizedRoot?.let { listOf(it) + segments.drop(1) } ?: emptyList()

/**
 * A source file as a path *under* the output directory, keeping its shape:
 * `/E:/work/cc/devtools/…/appimage.h` → `E/work/cc/devtools/…/appimage.h`. Separators, `..` and
 * relative spellings are already settled by the identity ([ghistabs.harvest.sourceFileOf]); all that
 * is left is the drive letter's colon, which is a path character on no filesystem we write to and becomes the top
 * directory without it. Segments are otherwise left alone — flattening the whole path into one name
 * spelled that header `E__work_cc_devtools_devtools-bluelab-7-0_result_include_imageutil_appimage.h`.
 *
 * Display, not identity: two sources that differ only in their drive letter's punctuation cannot
 * arise, so nothing collides here that Ghidra held apart.
 */
val GhidraSourceFile.outputPath get() = Path("", *sanitizedSegments.toTypedArray())

/**
 * C is declarator-based: an array's extent goes *after* the  * name, so `char const[18] ABC`
 * has to be `char const ABC[18]`.
 */
private val ARRAY_SUFFIX = Regex("""((?:\[[^\]]*\])+)$""")

fun declarator(type: String, name: String) = ARRAY_SUFFIX.find(type)
    ?.let { "${type.removeSuffix(it.value).trimEnd()} $name${it.value}" }
    ?: "$type $name"
