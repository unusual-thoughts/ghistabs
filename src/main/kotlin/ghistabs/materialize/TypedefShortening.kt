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

    /**
     * [shortenedOrNull] restricted to rewrites that happen *inside* [name] — null when the whole of it
     * is an alias target.
     *
     * `vector<basic_string<…>,…>` → `vector<string>` is only reachable by rewriting the name, since no
     * typedef names that instantiation. `basic_string<…>` on its own is not: the `string` typedef
     * already carries that spelling at every reference (see `registerNamedPrimitiveTypedefs`), and
     * renaming the type would land on the name its own typedef holds — the collision the fold path
     * existed to paper over. Renaming is for what substitution cannot reach.
     */
    fun shortenedNestedOrNull(name: String): String? =
        shortenedOrNull(name)?.takeIf { canonTemplateName(name) !in aliasByTarget }
}

/**
 * Ghidra base type — a built-in (`int`, `longlong`, `char *`) or an undefined placeholder. Never an
 * alias target: a `typedef long long fpos_t` must not rename `longlong` to `fpos_t`, and such short
 * names corrupt siblings by substring (`longlong` in `longlongint`, `undefined` in `undefined4`).
 *
 * A pointer inherits the answer from its pointee, rather than from its own class: `char *` / `void *`
 * are base types (`PVOID`, `LPSTR` must not claim them), but `_ACL *` is not — `PACL` is a name worth
 * having. Ghidra alone can't tell you this, because `PointerDataType extends BuiltIn` while `PointerDB
 * extends DataTypeDB`, so the bare `is BuiltInDataType` test answers differently for the same logical
 * type depending on whether it has been resolved yet. A pointee-less pointer counts as a base type.
 */
fun DataType.isGhidraBaseType(): Boolean = when (this) {
    is Pointer -> dataType?.isGhidraBaseType() != false
    else -> this is BuiltInDataType || Undefined.isUndefined(this)
}

/**
 * Typedef alias → the DTM name of the type it aliases, read off the stabs typedef declarations
 * (`namedPrimitiveTypedefs` — despite the name, every named non-XRef-target ast, which is exactly what
 * [registerNamedPrimitiveTypedefs] turns into DTM typedefs). Resolving the *declaration* rather than
 * reading a registered `TypeDef` back out of the DTM is what makes the two refusals exact: [resolveRef]
 * hands back the `byId`-cached object registration itself used, so this is the very DataType the
 * registry classified.
 *
 *  - A Ghidra base type is never an alias target ([isGhidraBaseType]).
 *  - Nor is an XRef stub (§21): a class no CU defined, so the alias is the only informative half.
 *    Folding the typedef into the empty placeholder loses it, and the registry's non-resident copy of
 *    the pair re-enters the DTM through a later apply as `<alias>.conflict` beside an empty struct
 *    wearing the alias. `ostream -> basic_ostream<…>` reads better than an empty `ostream` anyway.
 */
internal fun DataTypeRegistry.typedefAliases(): Map<String, String> =
    types.namedPrimitiveTypedefs.mapNotNull { (alias, asts) ->
        resolveRef(asts.first().body)
            ?.takeUnless { it.isGhidraBaseType() || it in xrefStubs }
            ?.let { alias to it.name }
    }.toMap()

/**
 * Datatype renames [TemplateNameShortener] would make over [typeNames] — one per name whose canonical
 * text shrinks. [nestedOnly] drops the whole-name rewrites, which the typedef carries at every
 * reference instead (see [TemplateNameShortener.shortenedNestedOrNull]).
 */
fun typedefShorteningRenames(
    aliases: Map<String, String>,
    typeNames: Set<String>,
    nestedOnly: Boolean = false,
): List<TypedefRename> = TemplateNameShortener(aliases).let { s ->
    typeNames.mapNotNull { name ->
        (if (nestedOnly) s.shortenedNestedOrNull(name) else s.shortenedOrNull(name))
            ?.let { TypedefRename(name, it) }
    }
}

/**
 * Opt-in pass that renames the long templated datatypes [registry] created onto their shorter typedef
 * aliases, so the listing and decompiler show `string` / `vector<string>` rather than the full
 * `basic_string<char, std::char_traits<char>, …>` spelling. Pure rename computation lives in
 * [typedefShorteningRenames]; this reads the aliases and names off the registry and applies them.
 *
 * Scoped to [DataTypeRegistry.allCreatedDataTypes] rather than the whole DTM: shortening
 * `unsigned char` to `BYTE` because Ghidra's PE loader applied `windows_vs12_32`, or renaming a
 * `/Demangler` stub out from under [ghistabs.importer.DemanglerReplacer], is not our business.
 */
class TypedefShortener(private val registry: DataTypeRegistry, private val monitor: TaskMonitor) :
    DiagnosticSink by registry {
    private val dtm = registry.dtm

    // Recomputed per read on the registry (pass C keeps registering) — snapshot once for this pass.
    private val byName by lazy { registry.allCreatedDataTypes.groupBy { it.name } }

    fun renames(): List<TypedefRename> = typedefShorteningRenames(
        registry.typedefAliases(),
        byName.keys,
        nestedOnly = true,
    )

    fun apply(): Int {
        val shortener = TemplateNameShortener(registry.typedefAliases())
        if (shortener.isEmpty) return 0
        val composites = byName.values.flatten().filterIsInstance<Composite>()
        monitor.initialize((byName.size + composites.size).toLong(), "Stabs: shortening typedefs")
        val typeRenamed = byName.keys.sumOf { name ->
            monitor.increment()
            shortener.shortenedNestedOrNull(name)
                ?.let { short -> byName.getValue(name).count { rename(it, short) } } ?: 0
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
