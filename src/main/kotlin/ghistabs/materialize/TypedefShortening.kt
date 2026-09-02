package ghistabs.materialize

import ghidra.program.model.data.*
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.itanium.Itanium
import ghistabs.parse.canonTemplateName

/** A rename the shortening pass performs: datatype simple name [from] → [to]. */
data class TypedefRename(val from: String, val to: String)

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
    private val aliasByTarget = aliases.entries
        .groupBy({ canonTemplateName(it.value) }, { it.key })
        .mapNotNull { (target, names) ->
            // Prefer a readable alias over compiler-internal shorthands: libstdc++'s explicit-
            // instantiation TUs emit `typedef basic_string<…> S;` and `__string_type`, and the raw
            // shortest-name rule picks `S` over `string`. Drop single-letter and `__`-reserved
            // names unless they're the only alias for this target.
            val readable = names.filterNot { it.length == 1 || it.startsWith("__") }
            readable.ifEmpty { names }.minBy { it.length }.takeIf { it.length < target.length }?.let { target to it }
        }
        .sortedByDescending { it.first.length }
        .toMap()

    // One alternation regex over all targets (longest first, so it prefers the outer match) — a single
    // Matcher per fixpoint pass instead of a fresh Regex.replace per alias over every name.
    private val combined = aliasByTarget.keys.takeIf { it.isNotEmpty() }?.let { keys ->
        Regex("(?<![A-Za-z0-9_])(" + keys.joinToString("|") { Regex.escape(it) } + ")(?![A-Za-z0-9_])")
    }

    // A name with no `<` can't contain any template target, so the fixpoint is a guaranteed no-op — skip
    // it (most created types aren't templated). Only valid when every target is itself templated.
    private val allTargetsTemplated = aliasByTarget.keys.all { '<' in it }
    private val cache = HashMap<String, String>()

    val isEmpty get() = aliasByTarget.isEmpty()

    /** Canonicalise [name] then substitute to a fixpoint; equals the canonical input when nothing shrank. */
    fun shorten(name: String): String = cache.getOrPut(name) { substitute(canonTemplateName(name)) }

    /**
     * Substitute aliases through [text] without canonicalising it — for a line of rendered code, where
     * [canonTemplateName]'s whitespace rule would also close up every `f(a, b)` and `a > b` it met.
     * Decompiler output already spells template names canonically (they come from the datatypes this
     * extension created), so the targets still match.
     */
    fun substitute(text: String): String {
        if (combined == null || (allTargetsTemplated && '<' !in text)) return text
        var s = text
        var prev: String
        do {
            prev = s
            s = combined.replace(s) { aliasByTarget.getValue(it.groupValues[1]) }
        } while (s != prev)
        return s
    }

    /** [shorten] but null unless the text actually shrank (below the canonical spelling of [name]). */
    fun shortenedOrNull(name: String): String? = shorten(name).takeIf { it.length < canonTemplateName(name).length }
}

/**
 * Ghidra base type — a built-in (`int`, `longlong`, `char *`) or an undefined placeholder. Never an
 * alias target: a `typedef long long fpos_t` must not rename `longlong` to `fpos_t`, and such short
 * names corrupt siblings by substring (`longlong` in `longlongint`, `undefined` in `undefined4`).
 */
fun DataType.isGhidraBaseType(): Boolean = this is BuiltInDataType || Undefined.isUndefined(this)

/** Typedef simple name → aliased type name, over [types], excluding typedefs onto a base type. */
fun typedefAliases(types: Iterable<DataType>): Map<String, String> = types.filterIsInstance<TypeDef>()
    .filter { !it.dataType.isGhidraBaseType() }
    .associate { it.name to it.dataType.name }

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
class TypedefShortener(
    private val dtm: DataTypeManager,
    private val monitor: TaskMonitor,
    sink: DiagnosticSink,
    private val stubNames: Set<String> = emptySet(),
) : DiagnosticSink by sink {
    private val allTypes by lazy { dtm.allDataTypes.asSequence().toList() }

    /**
     * A typedef the stabs importer created, as opposed to one Ghidra's PE loader applied from a
     * data-type archive (PVOID, BYTE, DWORD, CONTEXT, …). Only stabs typedefs should drive renames —
     * shortening `unsigned char` to `BYTE` because a Windows archive is loaded is not our business.
     * Stabs types live in the program-local source archive; applied archive types don't.
     */
    private fun DataType.isStabsOrigin(): Boolean =
        sourceArchive == null || sourceArchive.sourceArchiveID == dtm.localSourceArchive.sourceArchiveID

    /**
     * Typedef simple name → aliased type name, restricted to stabs typedefs that don't alias a base
     * type ([typedefAliases]) or an XRef stub ([stubNames]).
     *
     * A typedef onto a stub names a class no CU defined — libstdc++'s `ostream` on a binary that only
     * ever takes one by pointer. Renaming that empty placeholder onto the alias folds the typedef away
     * (the fold path in [rename], since the typedef *is* the stub's only namer), and the registry's
     * non-resident copy of the pair then re-enters the DTM through a later apply as `<alias>.conflict`
     * beside an empty struct wearing the alias. Keeping the typedef is also the better render:
     * `ostream -> basic_ostream<…>` says more than an empty `ostream`.
     */
    private fun aliases(types: List<DataType>): Map<String, String> =
        typedefAliases(types.filter { it.isStabsOrigin() }).filterValues { it !in stubNames }

    fun renames(): List<TypedefRename> = typedefShorteningRenames(
        aliases(allTypes),
        allTypes.mapTo(mutableSetOf()) { it.name },
    )

    fun apply(): Int {
        val shortener = TemplateNameShortener(aliases(allTypes))
        if (shortener.isEmpty) return 0
        val byName = allTypes.groupBy { it.name }
        val composites = allTypes.filterIsInstance<Composite>()
        monitor.initialize((byName.size + composites.size).toLong(), "Stabs: shortening typedefs")
        val typeRenamed = byName.keys.sumOf { name ->
            monitor.increment()
            shortener.shortenedOrNull(name)?.let { short -> byName.getValue(name).count { rename(it, short) } } ?: 0
        }
        // Base-class subobject fields (`_base_<Name>`/`_vbase_<Name>`) embed the base type's name at
        // build time, so renaming the base datatype never reaches them — rewrite those field names too.
        val fieldRenamed = composites.sumOf { c ->
            monitor.increment()
            c.components.count { it.shortenBaseField(shortener) }
        }
        log("typedef-shorten", "renamed $typeRenamed datatypes, $fieldRenamed base fields")
        return typeRenamed + fieldRenamed
    }

    private fun DataTypeComponent.shortenBaseField(shortener: TemplateNameShortener): Boolean {
        val name = fieldName ?: return false
        if (!Itanium.isBaseField(name)) return false
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
                .onFailure { debug("typedef-shorten-skip", "fold ${conflict.pathName}: ${it.message}") }
            return runCatching { dt.name = to }.isSuccess
        }
        debug("typedef-shorten-skip", "${dt.pathName} -> $to: name held by ${conflict?.pathName ?: "?"}")
        return false
    }
}
