package ghistabs.materialize

import ghidra.program.model.data.BuiltInDataType
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeComponent
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.TypeDef
import ghidra.program.model.data.Undefined
import ghistabs.diagnose.DiagnosticSink

/** A rename the shortening pass performs: datatype simple name [from] → [to]. */
data class TypedefRename(val from: String, val to: String)

/** Whitespace around template punctuation — gcc is inconsistent (`< `, `, `, ` >`, `> >`). */
private val TEMPLATE_PUNCT = Regex("""\s*([<>,])\s*""")

/** Canonical spelling of a templated name: no whitespace around `<`, `>`, `,` (multi-word types like `short unsigned int` keep their spaces). */
fun canonTemplateName(name: String): String = TEMPLATE_PUNCT.replace(name.trim()) { it.groupValues[1] }

/**
 * Collapses long templated names onto shorter typedef aliases.
 *
 * [aliases] maps each typedef's simple name to the simple name of the type it aliases. A typedef
 * qualifies when its name is shorter than its canonicalised target; each qualifying target is
 * rewritten to its alias wherever it appears — longest target first so nested reductions compose
 * (`vector<basic_string<…> >` → `vector<string>`), shortest alias winning when several name one
 * target. Matching is identifier-boundary-guarded so a bare-identifier target can't rewrite a
 * substring of a longer name (`longlong` in `longlongint`, `undefined` in `undefined4`); the
 * `>`-terminated template targets still match, bounded by `<`, `,`, `::` or edges.
 */
class TemplateNameShortener(aliases: Map<String, String>) {
    private val guarded = aliases.entries
        .groupBy({ canonTemplateName(it.value) }, { it.key })
        .mapNotNull { (target, names) ->
            names.minBy { it.length }.takeIf { it.length < target.length }?.let { target to it }
        }
        .sortedByDescending { it.first.length }
        .map { (target, alias) -> Regex("(?<![A-Za-z0-9_])${Regex.escape(target)}(?![A-Za-z0-9_])") to alias }

    val isEmpty get() = guarded.isEmpty()

    /** Canonicalise [name] then substitute to a fixpoint; equals the canonical input when nothing shrank. */
    fun shorten(name: String): String {
        var s = canonTemplateName(name)
        var prev: String
        do {
            prev = s
            for ((re, alias) in guarded) s = re.replace(s) { alias }
        } while (s != prev)
        return s
    }

    /** [shorten] but null unless the text actually shrank (below the canonical spelling of [name]). */
    fun shortenedOrNull(name: String): String? = shorten(name).takeIf { it.length < canonTemplateName(name).length }
}

/** Datatype renames [TemplateNameShortener] would make over [typeNames] — one per name whose canonical text shrinks. */
fun typedefShorteningRenames(aliases: Map<String, String>, typeNames: Set<String>): List<TypedefRename> =
    TemplateNameShortener(aliases).let { s ->
        typeNames.mapNotNull { name -> s.shortenedOrNull(name)?.let { TypedefRename(name, it) } }
    }

/**
 * Opt-in DTM pass that renames long templated datatypes onto their shorter typedef aliases, so the
 * listing and decompiler show `string` / `vector<string>` rather than the full
 * `basic_string<char, std::char_traits<char>, …>` spelling. Pure rename computation lives in
 * [typedefShorteningRenames]; this reads the aliases and names out of the DTM and applies them.
 */
class TypedefShortener(private val dtm: DataTypeManager, private val sink: DiagnosticSink) {
    private fun allTypes(): List<DataType> = dtm.allDataTypes.asSequence().toList()

    /**
     * A typedef the stabs importer created, as opposed to one Ghidra's PE loader applied from a
     * data-type archive (PVOID, BYTE, DWORD, CONTEXT, …). Only stabs typedefs should drive renames —
     * shortening `unsigned char` to `BYTE` because a Windows archive is loaded is not our business.
     * Stabs types live in the program-local source archive; applied archive types don't.
     */
    private fun DataType.isStabsOrigin(): Boolean =
        sourceArchive == null || sourceArchive.sourceArchiveID == dtm.localSourceArchive.sourceArchiveID

    /**
     * Ghidra base type — a built-in (`int`, `longlong`, `char *`, …) or an undefined placeholder
     * (`undefined`, `undefined4`). Never shorten these: a stabs `typedef long long fpos_t` must not
     * rename Ghidra's `longlong` to `fpos_t`, and their short names also corrupt siblings by
     * substring (`longlong` inside `longlongint`, `undefined` inside `undefined4`).
     */
    private fun DataType.isGhidraBaseType(): Boolean = this is BuiltInDataType || Undefined.isUndefined(this)

    /** Typedef simple name → aliased type name, restricted to stabs typedefs that don't alias a base type. */
    private fun aliases(types: List<DataType>): Map<String, String> = types.asSequence()
        .filterIsInstance<TypeDef>()
        .filter { it.isStabsOrigin() && !it.dataType.isGhidraBaseType() }
        .associate { it.name to it.dataType.name }

    fun renames(): List<TypedefRename> {
        val types = allTypes()
        return typedefShorteningRenames(aliases(types), types.mapTo(mutableSetOf()) { it.name })
    }

    fun apply(): Int {
        val types = allTypes()
        val shortener = TemplateNameShortener(aliases(types))
        if (shortener.isEmpty) return 0
        val byName = types.groupBy { it.name }
        val typeRenamed = byName.keys.sumOf { name ->
            shortener.shortenedOrNull(name)?.let { short -> byName.getValue(name).count { rename(it, short) } } ?: 0
        }
        // Base-class subobject fields (`_base_<Name>`/`_vbase_<Name>`) embed the base type's name at
        // build time, so renaming the base datatype never reaches them — rewrite those field names too.
        val fieldRenamed = types.filterIsInstance<Composite>()
            .sumOf { c -> c.components.count { it.shortenBaseField(shortener) } }
        sink.log("typedef-shorten", "renamed $typeRenamed datatypes, $fieldRenamed base fields")
        return typeRenamed + fieldRenamed
    }

    private fun DataTypeComponent.shortenBaseField(shortener: TemplateNameShortener): Boolean {
        val name = fieldName ?: return false
        if (!name.startsWith("_base_") && !name.startsWith("_vbase_")) return false
        val short = shortener.shortenedOrNull(name) ?: return false
        return runCatching { fieldName = short }.isSuccess
    }

    /**
     * Rename [dt] to [to]. The alias frequently already lives in [dt]'s own category as the very
     * typedef pointing at [dt] (`string` → `basic_string<…>`): renaming would collide. Fold that
     * typedef into [dt] first — [DataTypeManager.replaceDataType] redirects every reference and
     * drops the typedef — which frees the name.
     */
    private fun rename(dt: DataType, to: String): Boolean {
        if (runCatching { dt.name = to }.isSuccess) return true
        val conflict = dtm.getDataType(dt.categoryPath, to)
        if (conflict is TypeDef && conflict.dataType == dt) {
            runCatching { dtm.replaceDataType(conflict, dt, false) }
                .onFailure { sink.log("typedef-shorten-skip", "fold ${conflict.pathName}: ${it.message}") }
            return runCatching { dt.name = to }.isSuccess
        }
        sink.log("typedef-shorten-skip", "${dt.pathName} -> $to: name held by ${conflict?.pathName ?: "?"}")
        return false
    }
}
