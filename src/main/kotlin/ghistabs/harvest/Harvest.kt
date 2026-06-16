package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.diagnose.Level
import ghistabs.parse.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class Harvest(
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    val parseErrors: Int = 0,
    var collidingAsts: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = mapOf(),
    val symbolsByCu: Map<String, List<HarvestedSymbol>> = mapOf(),
    val openFunctions: List<OpenFunction> = listOf(),
    @Transient val sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    @Transient
    val hashCache: MutableMap<GlobalTypeId, Int> = mutableMapOf()

    val allHarvestedSymbols by lazy { symbolsByCu.values.flatten() }

    /**
     * Strip template arguments and namespace qualifiers from a class name.
     *
     *   `basic_istream<char,std::char_traits<char>>` → `basic_istream`
     *   `std::basic_istream`                          → `basic_istream`
     *   `__gnu_cxx::__normal_iterator<char*,…>`       → `__normal_iterator`
     *
     * Used by the XRef base-tag fallback to bridge "forward-declared bare tag in one
     * CU vs full template instantiation in another" — the cross-CU mismatch is
     * structural in gcc stabs, not a libstdc++-version detail, so this helper has no
     * hardcoded names.
     */
    private fun baseTag(name: String): String {
        val noArgs = name.indexOf('<').let { if (it >= 0) name.substring(0, it) else name }
        return noArgs.trim().substringAfterLast("::")
    }

    /** Group ASTs once by Ghidra-sanitised name (only space is invalid; cf. SymbolUtilities.INVALIDCHARS). */
    val astsByGhidraName by lazy { typeAsts.values.groupBy { it.ghidraName } }

    /**
     * All named aggregate / enum ASTs harvested in Pass A, indexed by raw stabs name.
     * Covers `TypeDecl.Struct` (struct/union/class via `kind`) and `TypeDecl.Enum` —
     * an XRef with `kind = ENUM` resolves through the same index.
     *
     * Multi-CU collisions on the same name are common: list, kind-filter at lookup.
     */
    private val astsByName: Map<String, List<TypeAst>> by lazy {
        typeAsts.values.filter { it.name.isNotEmpty() && it.body.isXRefTarget }.groupBy { it.name }
    }

    /**
     * Secondary index for XRef resolution: base-tag (template args + namespace stripped).
     * Bridges `XRef(STRUCT, "basic_istream")` ↔ `basic_istream<char,…>` (gdb
     * `check_typedef()` / TYPE_TAG_NAME territory). Same kind coverage as [astsByName],
     * skip incomplete definitions (forward-decl-shaped) — no point falling back to
     * another forward decl.
     */
    private val astsByBaseTag: Map<String, List<TypeAst>> by lazy {
        typeAsts.values
            .filter { it.name.isNotEmpty() && it.body.isXRefTarget && it.body.isComplete }
            .groupBy { baseTag(it.name) }
    }

    fun getType(id: GlobalTypeId) = typeAsts[id]
    fun getStruct(id: GlobalTypeId) = typeAsts[id]?.body as? TypeDecl.Struct

    /**
     * Canonical (CategoryPath, ghidraName) view — Ghidra's uniqueness key.
     * Built only from registerable bodies (Struct/Enum); derived types
     * never occupy a stable slot. See docs/notes/canonical-key.md.
     */
    val byCanonicalKey: Map<Pair<CategoryPath, String>, CanonicalGroup> by lazy {
        val registerable = typeAsts.values.filter { it.body.isXRefTarget }
        val byGhidraName = registerable.groupBy { it.ghidraName }
        val categoryByGhidraName = byGhidraName.mapValues { (name, asts) ->
            Attribution.categoryFor(name, asts.map { it.id.source }.toSet())
        }
        registerable
            .groupBy { categoryByGhidraName.getValue(it.ghidraName) to it.ghidraName }
            .mapValues { (key, members) -> classifyGroup(key, members) }
    }

    private fun classifyGroup(key: Pair<CategoryPath, String>, members: List<TypeAst>): CanonicalGroup {
        val distinctKinds = members.map { it.body::class }.toSet()
        if (distinctKinds.size > 1) {
            log(
                "canonical-key-multi-kind",
                "${key.first}/${key.second}: ${distinctKinds.map { it.simpleName }}",
                Level.WARN,
            )
        }
        val byHash = members.groupBy { contentHash(it.body) }
        when {
            byHash.size > 1 -> log(
                "canonical-key-multi-hash",
                "${key.first}/${key.second}: ${byHash.size} distinct bodies across " +
                    members.map { it.id.source.filename }.toSet(),
                Level.INFO,
            )

            members.size > 1 -> log(
                "canonical-key-merged",
                "${key.first}/${key.second}: ${members.size} ASTs collapsed (single body)",
                Level.DEBUG,
            )
        }
        // Winner: largest body, then first by source filename for stability.
        val winner = members.maxWithOrNull(
            compareBy<TypeAst> { it.body.sizeBytes }.thenBy { it.id.source.filename },
        )!!
        return CanonicalGroup(key, members, winner)
    }

    /**
     * XRef → canonical struct.
     *  1. Exact-name lookup (the common case: two CUs both name the same class identically).
     *  2. Base-tag fallback: strip namespace prefix and template args, find a complete
     *     definition with the same base name and matching kind. Only used when the
     *     candidates of the right kind are unambiguous *by size* — multiple distinct
     *     sizes mean we'd be picking among template instantiations (tinyxml2's
     *     `DynArray<char,20>` vs `DynArray<PKc,10>`); picking the wrong one would
     *     fail downstream `replaceAtOffset` calls with the wrong byte count.
     *     Logged at DEBUG when it fires, `xref-base-tag-ambiguous` at INFO when
     *     candidates exist but differ in size.
     *
     *     Mirrors GDB's check_typedef() walk over stub types via TYPE_TAG_NAME but
     *     without committing to a specific instantiation when the harvest doesn't
     *     uniquely identify one.
     */
    fun getByXRef(xref: TypeDecl.XRef<GlobalTypeId>): TypeAst? {
        astsByName[xref.tagName]
            ?.firstOrNull { it.body.matchesXRefKind(xref.kind) }
            ?.let { return it }

        val tag = baseTag(xref.tagName)
        if (tag.isNotEmpty()) {
            val candidates = astsByBaseTag[tag]?.filter { it.body.matchesXRefKind(xref.kind) }.orEmpty()
            val distinctSizes = candidates.map { it.body.sizeBytes }.toSet()
            when {
                candidates.isEmpty() -> Unit

                distinctSizes.size == 1 -> {
                    val resolved = candidates.first()
                    log("xref-base-tag-resolved", "'${xref.tagName}' → '${resolved.name}'", Level.DEBUG)
                    return resolved
                }

                else -> log(
                    "xref-base-tag-ambiguous",
                    "'${xref.tagName}': ${candidates.size} candidates with sizes $distinctSizes; refusing fallback",
                )
            }
        }

        log("unresolved-xref", "${xref.tagName} [${xref.kind}]", Level.WARN)
        return null
    }

    /**
     * Content-equivalence hash for a [TypeDecl] tree, using `typeAsts`
     * (plus the name-keyed XRef index) as the oracle. See the top-level
     * [contentHash] for semantics.
     */
    fun contentHash(body: TypeDecl<GlobalTypeId>): Int = body.contentHash(oracle, hashCache)

    /** Oracle exposing both id-based and name-based (XRef) lookups. */
    val oracle: TypeAstOracle by lazy { TypeAstOracle(byId = typeAsts::get, byXRef = ::getByXRef) }

    /**
     * Classify [collidingAsts] entries by whether their alternate bodies
     * are content-equivalent. Pre-warms [cache] by hashing every typeAst
     * body top-level first so cache state doesn't bias the result.
     *
     * Cache-pollution failure mode this avoids: with a cold cache the
     * first variant computed seeds cache entries for transitively-
     * referenced ids using a visited set that already contains the
     * colliding id, so inner self-Refs back-edge instead of recursing.
     * Subsequent variants then cache-hit those stale values, and
     * structurally-identical Ref-vs-InlineDef forms diverge purely on
     * cache state. Pre-warming with empty visited sets fixes this.
     */
    fun classifyCollisions() {
        // Classify collisions and drop the spurious (content-equivalent)
        // buckets before the Harvest is published. Downstream consumers
        // only ever see genuinely-divergent collisions; the warmed cache
        // is handed off to the Harvest so TypeRegistry doesn't redo the
        // hash work, and the stats ride along on `harvest.classification`.

        for (ast in typeAsts.values) {
            hashCache[ast.id] = contentHash(ast.body)
        }
        collidingAsts = collidingAsts.filterValues { byName ->
            byName.values.flatten().map { contentHash(it) }.toSet().size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                types.groupBy { contentHash(it) }.map { it.value.first() }.toSet()
            }
        }.toMap()
    }
}
