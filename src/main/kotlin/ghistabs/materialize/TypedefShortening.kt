package ghistabs.materialize

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.TypeDef
import ghistabs.diagnose.DiagnosticSink

/** A rename the shortening pass performs: datatype simple name [from] → [to]. */
data class TypedefRename(val from: String, val to: String)

/** Whitespace around template punctuation — gcc is inconsistent (`< `, `, `, ` >`, `> >`). */
private val TEMPLATE_PUNCT = Regex("""\s*([<>,])\s*""")

/** Canonical spelling of a templated name: no whitespace around `<`, `>`, `,` (multi-word types like `short unsigned int` keep their spaces). */
fun canonTemplateName(name: String): String = TEMPLATE_PUNCT.replace(name.trim()) { it.groupValues[1] }

/**
 * Collapse long templated type names onto shorter typedef aliases.
 *
 * [aliases] maps each typedef's simple name to the simple name of the type it aliases; [typeNames]
 * is every datatype simple name in play. A typedef qualifies when its name is shorter than its
 * canonicalised target. Each qualifying target is rewritten to its alias wherever it appears — the
 * target type itself and, recursively, inside every other templated name's parameters — longest
 * target first so nested reductions compose (`vector<basic_string<…> >` → `vector<string>`).
 * Returns one [TypedefRename] per name whose canonical text actually shrinks.
 */
fun typedefShorteningRenames(aliases: Map<String, String>, typeNames: Set<String>): List<TypedefRename> {
    val subs = aliases.entries
        .map { canonTemplateName(it.value) to it.key }
        .filter { (target, alias) -> alias.length < target.length }
        .sortedByDescending { it.first.length }
    if (subs.isEmpty()) return emptyList()

    fun rewrite(name: String): String {
        var s = canonTemplateName(name)
        var prev: String
        do {
            prev = s
            for ((target, alias) in subs) s = s.replace(target, alias)
        } while (s != prev)
        return s
    }

    return typeNames.mapNotNull { name ->
        rewrite(name).takeIf { it.length < canonTemplateName(name).length }?.let { TypedefRename(name, it) }
    }
}

/**
 * Opt-in DTM pass that renames long templated datatypes onto their shorter typedef aliases, so the
 * listing and decompiler show `string` / `vector<string>` rather than the full
 * `basic_string<char, std::char_traits<char>, …>` spelling. Pure rename computation lives in
 * [typedefShorteningRenames]; this reads the aliases and names out of the DTM and applies them.
 */
class TypedefShortener(private val dtm: DataTypeManager, private val sink: DiagnosticSink) {
    private fun allTypes(): List<DataType> = dtm.allDataTypes.asSequence().toList()

    fun renames(): List<TypedefRename> {
        val types = allTypes()
        val aliases = types.filterIsInstance<TypeDef>().associate { it.name to it.dataType.name }
        return typedefShorteningRenames(aliases, types.mapTo(mutableSetOf()) { it.name })
    }

    fun apply(): Int {
        val byName = allTypes().groupBy { it.name }
        return renames().sumOf { (from, to) ->
            byName[from].orEmpty().count { dt ->
                runCatching { dt.name = to }
                    .onFailure { sink.log("typedef-shorten-skip", "$from -> $to: ${it.message}") }
                    .isSuccess
            }
        }.also { sink.log("typedef-shorten", "renamed $it datatypes") }
    }
}
