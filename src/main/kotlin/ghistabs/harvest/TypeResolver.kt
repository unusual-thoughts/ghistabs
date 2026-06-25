package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.parse.*

/**
 * Indexes the [Harvest]'s typeAsts: id/xref oracle for [contentHash], xref resolution with
 * per-reason failure counters, canonical-key grouping for TypeRegistry slot assignment,
 * and content-distinct collision filtering.
 */
class TypeResolver(
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    private val rawCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = emptyMap(),
    private val sink: DiagnosticSink = DummySink,
    private val diagnostics: StabsDiagnostics = StabsDiagnostics(),
    private val harvest: Harvest? = null,
) : TypeAstOracle {
    /** All named aggregate / enum ASTs, indexed by raw stabs name. */
    private val astsByName: Map<String, List<TypeAst>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget }
            .groupBy { it.name!! }
    }

    /** Base-tag (template args + namespace stripped) → complete definitions only. */
    private val astsByBaseTag: Map<String, List<TypeAst>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget && it.body.isComplete }
            .groupBy { QualifiedName.baseTag(it.name!!) }
    }

    private val hashCache: MutableMap<GlobalTypeId, Int> by lazy {
        // Pre-warm with empty `visited` so collision classification isn't biased by traversal order.
        mutableMapOf<GlobalTypeId, Int>().also { c ->
            for (ast in typeAsts.values) c[ast.id] = ast.body.contentHash(this, c)
        }
    }

    override fun byId(id: GlobalTypeId): TypeAst? = typeAsts[id]

    /** Convenience: id → struct body (null if not a struct). */
    fun getStruct(id: GlobalTypeId): TypeDecl.Struct<GlobalTypeId>? = typeAsts[id]?.body as? TypeDecl.Struct

    override fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>): TypeAst? = lookupByXRef(xref, silent = true)

    /**
     * Resolve [xref] to its canonical [TypeAst]. Tries exact-name, then base-tag fallback
     * (commits only when all same-kind candidates agree on size). On miss bumps
     * `xref-undefined` / `xref-kind-mismatch` / `xref-ambiguous`. [silent] is for the
     * contentHash oracle path which expects misses.
     */
    fun lookupByXRef(xref: TypeDecl.XRef<GlobalTypeId>, silent: Boolean = false): TypeAst? {
        astsByName[xref.tagName]
            ?.firstOrNull { it.body.matchesXRefKind(xref.kind) }
            ?.let { return it }

        val tag = QualifiedName.baseTag(xref.tagName)
        val sameTagAnyKind = if (tag.isNotEmpty()) astsByBaseTag[tag].orEmpty() else emptyList()
        val sameKind = sameTagAnyKind.filter { it.body.matchesXRefKind(xref.kind) }
        val distinctSizes = sameKind.map { it.body.sizeBytes }.toSet()

        if (sameKind.isNotEmpty() && distinctSizes.size == 1) {
            val resolved = sameKind.first()
            sink.log("xref-base-tag-resolved", "'${xref.tagName}' → '${resolved.nameOrUnique}'", Level.DEBUG)
            return resolved
        }

        if (silent) return null

        val exactAnyKind = astsByName[xref.tagName].orEmpty()
        val counter = when {
            sameKind.isNotEmpty() -> {
                sink.log(
                    "xref-base-tag-ambiguous",
                    "'${xref.tagName}': ${sameKind.size} candidates with sizes $distinctSizes; refusing fallback",
                )
                "xref-ambiguous"
            }

            sameTagAnyKind.isNotEmpty() || exactAnyKind.isNotEmpty() -> "xref-kind-mismatch"

            else -> "xref-undefined"
        }
        diagnostics.inc(counter)
        sink.log("unresolved-xref", "${xref.tagName} [${xref.kind}] ${xrefDiagnosis(xref)}", Level.WARN)
        return null
    }

    /** One-line snapshot of harvest contents under [xref]'s exact tag and base tag. */
    private fun xrefDiagnosis(xref: TypeDecl.XRef<GlobalTypeId>): String {
        val tag = QualifiedName.baseTag(xref.tagName)
        val exact = astsByName[xref.tagName].orEmpty()
        val byBase = astsByBaseTag[tag].orEmpty()
        fun summarise(asts: List<TypeAst>): String {
            if (asts.isEmpty()) return "0"
            val parts = asts.groupBy { it.body::class.simpleName }
                .map { (k, v) ->
                    val sizes = v.mapNotNull { (it.body as? TypeDecl.Struct)?.sizeBytes }.toSortedSet()
                    val names = v.map { it.name }.toSet().joinToString("|").take(120)
                    "$k×${v.size} sizes=$sizes names=[$names]"
                }
            return "${asts.size}{${parts.joinToString("; ")}}"
        }
        return "exact=${summarise(exact)} baseTag='$tag' byBaseTag=${summarise(byBase)}"
    }

    /** Content hash of [body] under this resolver's oracle, sharing the canonicalization cache. */
    fun contentHash(body: TypeDecl<GlobalTypeId>): Int = body.contentHash(this, hashCache)

    /** Multi-body collisions after content-equivalence filtering — only genuinely divergent ones. */
    val divergentCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> by lazy {
        rawCollisions.filterValues { byName ->
            byName.values.flatten().map { contentHash(it) }.toSet().size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                types.groupBy { contentHash(it) }.map { it.value.first() }.toSet()
            }
        }
    }

    /**
     * For multi-CU classes whose direct sources are all .cpp, infer the owning header by
     * majority vote over the source attribution of N_SLINE entries inside the type's member
     * function bodies — gcc emits `N_SOL("foo.h")` bursts inside each method that inlines
     * header code, so the line entries point back at the declaring header.
     */
    val multiSourceHeaderHints: Map<String, String> by lazy {
        val h = harvest ?: return@lazy emptyMap()
        if (h.openFunctions.isEmpty() || h.lineEntries.isEmpty()) return@lazy emptyMap()
        val funcsByMangled = h.openFunctions.filter { it.sizeBytes > 0 }.associateBy { it.name }
        // Skip lookups for sources that are the type's own definition CU: those win by
        // sheer body-size and would short-circuit the heuristic.
        val cuSourcesByName = typeAsts.values
            .filter { it.name != null }
            .groupBy({ it.name!! }, { it.id.source.filename })
            .mapValues { it.value.toSet() }
        val out = mutableMapOf<String, String>()
        for ((name, asts) in astsByName) {
            // Only types with >1 distinct CU source need a hint — single-source types
            // already attribute correctly via Attribution's uniquePaths path.
            val cuSources = cuSourcesByName[name] ?: continue
            if (cuSources.size < 2) continue
            val methods = asts.flatMap { (it.body as? TypeDecl.Struct<*>)?.methods.orEmpty() }
            if (methods.isEmpty()) continue
            val tally = mutableMapOf<String, Int>()
            for (m in methods) {
                val func = funcsByMangled[m.mangled ?: continue] ?: continue
                val lo = func.addr.address.offset
                val hi = lo + func.sizeBytes
                for ((src, entries) in h.lineEntries) {
                    if (src in cuSources) continue
                    if (!src.hasHeaderExtension()) continue
                    for (e in entries) {
                        val a = e.addr.address.offset
                        if (a in lo until hi) tally.merge(src, 1, Int::plus)
                    }
                }
            }
            tally.maxByOrNull { it.value }?.let { out[name] = it.key }
        }
        out
    }

    /** Canonical (CategoryPath, ghidraName) → group. Drives TypeRegistry slot assignment. */
    val byCanonicalKey: Map<GhidraKey, CanonicalGroup> by lazy {
        val byGhidraName = typeAsts.values.groupBy { it.ghidraName }
        val attribution = Attribution(
            commonProjectPrefix = commonProjectPrefix(typeAsts.values.map { it.id.source }),
            multiSourceHeaderHints = multiSourceHeaderHints,
        )
        typeAsts.values
            .filter { it.body.isXRefTarget }
            .groupBy { ast ->
                attribution.keyForAst(
                    ast,
                    byGhidraName.getValue(ast.ghidraName).map { it.id.source }.toSet(),
                )
            }
            .mapValues { (key, members) -> classifyGroup(key, members) }
    }

    private fun classifyGroup(key: GhidraKey, members: List<TypeAst>): CanonicalGroup {
        val distinctKinds = members.map { it.body::class }.toSet()
        if (distinctKinds.size > 1) {
            sink.log(
                "canonical-key-multi-kind",
                "$key: ${distinctKinds.map { it.simpleName }}",
                Level.WARN,
            )
        }
        val byHash = members.groupBy { contentHash(it.body) }
        when {
            byHash.size > 1 -> sink.log(
                "canonical-key-multi-hash",
                "$key: ${byHash.size} distinct bodies across " +
                    members.map { it.id.source.filename }.toSet(),
                Level.INFO,
            )

            members.size > 1 -> sink.log(
                "canonical-key-merged",
                "$key: ${members.size} ASTs collapsed (single body)",
                Level.DEBUG,
            )
        }
        // Winner: largest body → fewest unresolved Refs → first by source filename (stable tiebreak).
        // Fewest-unresolved picks the most-resolved variant when CUs disagree on gcc-implicit slots.
        val winner = members.maxWithOrNull(
            compareBy<TypeAst> { it.body.sizeBytes }
                .thenByDescending { countUnresolvedRefs(it.body) }
                .thenBy { it.id.source.filename },
        )!!
        return CanonicalGroup(key, winner, members.map { it.id }, byHash.size)
    }

    private fun countUnresolvedRefs(body: TypeDecl<GlobalTypeId>): Int {
        if (body !is TypeDecl.Struct) return 0
        return body.fields.count { f -> walksToUnresolvedRef(f.type) }
    }

    private tailrec fun walksToUnresolvedRef(t: TypeDecl<GlobalTypeId>): Boolean = when (t) {
        is TypeDecl.Ref -> t.id !in typeAsts
        is TypeDecl.InlineDef -> walksToUnresolvedRef(t.body)
        is TypeDecl.Pointer -> walksToUnresolvedRef(t.pointee)
        is TypeDecl.Reference -> walksToUnresolvedRef(t.referent)
        is TypeDecl.Const -> walksToUnresolvedRef(t.inner)
        is TypeDecl.Volatile -> walksToUnresolvedRef(t.inner)
        else -> false
    }

    companion object {
        /** Empty resolver — useful for tests that only need oracle defaults. */
        val Empty = TypeResolver(emptyMap())
    }
}
