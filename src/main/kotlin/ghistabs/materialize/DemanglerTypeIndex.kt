package ghistabs.materialize

import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.TypeDef
import ghistabs.diagnose.DiagnosticSink

/**
 * Resolves a GNU-demangler stub's simple name to one of our stab-derived datatypes, bridging the two
 * spellings of the same C++ type. The demangler keeps STL typedef shorthand and spells template const
 * east, glued (`std::string const` → `std::string_const`); gcc's stabs expand the typedef
 * (`std::basic_string<char, …>`) and spell const west, glued (`conststd::…`). [normalizedSpelling]
 * reduces both to one form so a stub still finds its type.
 *
 * [exactMatches] returns the registry's own name-indexed hits (checked first, so exact names never go
 * through normalization); [createdTypes] is every datatype we materialised, indexed here by normalized
 * spelling as the fallback bucket.
 */
class DemanglerTypeIndex(
    private val createdTypes: Set<DataType>,
    sink: DiagnosticSink,
    private val exactMatches: (String) -> List<DataType>,
) : DiagnosticSink by sink {
    /** Folds our typedef targets onto their aliases (`std::basic_string<…>` → `std::string`) — see [normalizedSpelling]. */
    private val nameShortener by lazy { TemplateNameShortener(typedefAliases(createdTypes)) }

    /**
     * [createdTypes] grouped by [normalizedSpelling] — the fallback index. `iterator` and
     * `const_iterator` stay in distinct buckets, each matchable, since const is kept.
     */
    private val byNormalizedName: Map<String, List<DataType>> by lazy {
        createdTypes.groupBy { normalizedSpelling(it.name) }
    }

    fun findByName(simpleName: String, preferredCategory: CategoryPath? = null): DataType? {
        val exact = exactMatches(simpleName)
        // Typedef-expansion / east-west-const mismatch: an exact miss may still be the same type under
        // the demangler's shorthand+east spelling. Only trust a unique bucket — const-variant pairs
        // and same-shape distinct instantiations stay ambiguous.
        val viaNormalized = exact.isEmpty()
        val matches = exact.ifEmpty { byNormalizedName[normalizedSpelling(simpleName)].orEmpty() }
        if (matches.isEmpty()) return null
        if (matches.size == 1) {
            return matches.single().also {
                if (viaNormalized) debug("demangler-normalized-match", "$simpleName -> ${it.pathName}")
            }
        }
        if (preferredCategory != null) {
            matches.firstOrNull { it.categoryPath == preferredCategory }?.let { return it }
        }
        // A typedef and its own resolved target both matching is not real ambiguity: typedef
        // shortening (OPT_SHORTEN_TYPEDEFS) renames the target struct onto the typedef's name
        // (`basic_string<…>` → `string`), so both a `string` typedef and a `string` struct — the
        // same type in two guises — end up named "string". Drop the target(s) a matching typedef
        // points at and keep the typedef, so the demangler stub is still replaceable (render-backlog §14).
        val typedefTargets = matches.filterIsInstance<TypeDef>().mapTo(mutableSetOf()) { it.baseDataType.pathName }
        val collapsed = matches.filterNot { it.pathName in typedefTargets }
        if (collapsed.size == 1) return collapsed.single()
        log(
            "demangler-ambiguous",
            "Multiple matches for '$simpleName' (preferred=$preferredCategory): " +
                matches.joinToString { "${it.pathName}(${it::class.simpleName})" },
        )
        return null
    }

    /**
     * A demangler stub name and our stab name for the same type, reduced to one spelling. Shorten
     * first — folding `std::basic_string<char, …>` onto `std::string` collapses the template to a
     * leaf — then [normalizeConst], which relies on that leaf to relocate west const without landing
     * inside template args.
     */
    private fun normalizedSpelling(name: String): String = normalizeConst(nameShortener.shorten(name))

    /**
     * Reduce cv-const spelling to the demangler's east form, glued: `conststd::string` and
     * `std::string_const` both become `std::stringconst`. West const (source spelling) is relocated
     * after the leaf type it qualifies — a boundary-anchored identifier run, since const only
     * qualifies a leaf here (templates are folded by [normalizedSpelling] first); east const just loses
     * its `_`/space separator. Const is kept, so const/non-const variants stay distinct.
     */
    private fun normalizeConst(name: String): String = name.replace(" const", "const").replace("_const", "const")
        .replace(EAST_CONST_LEAF) { "${it.groupValues[1]}const" }

    private companion object {
        /** West `const<leaf>` at a type-start boundary → captures the leaf for east relocation. */
        val EAST_CONST_LEAF = Regex("(?<=[<,(&*]|^)const([\\w:]+)")
    }
}
