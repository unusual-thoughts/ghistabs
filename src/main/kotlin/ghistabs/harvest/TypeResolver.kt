package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.QualifiedName
import ghistabs.parse.TypeDecl
import ghistabs.parse.isComplete
import ghistabs.parse.isXRefTarget
import ghistabs.parse.matchesXRefKind
import ghistabs.parse.sizeBytes

/**
 * Indexes the [Harvest]'s typeAsts for downstream consumers:
 *
 *  - [TypeAstOracle] implementation for [contentHash] (id + xref).
 *  - [lookupByXRef] for materialiser-time XRef resolution. Records degradations
 *    at the lookup site so callers never need to bucket failure reasons.
 *  - [byCanonicalKey] — the (CategoryPath, name) → CanonicalGroup mapping that
 *    drives Ghidra slot assignment in TypeRegistry. Computed lazily.
 *  - [divergentCollisions] — the [Harvest.rawCollisions] filtered down to
 *    content-distinct buckets (content-equivalent duplicates dropped via the
 *    same hashCache that warms canonicalization).
 *
 * The hashCache stays private; canonicalization is the only consumer.
 *
 * Sink + diagnostics are taken at construction time so degradations get
 * recorded in the same context as the rest of the importer. Tests that don't
 * care can leave them defaulted.
 */
class TypeResolver(
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    private val rawCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = emptyMap(),
    private val sink: DiagnosticSink = DummySink,
    private val diagnostics: StabsDiagnostics = StabsDiagnostics(),
) : TypeAstOracle {
    /** All named aggregate / enum ASTs, indexed by raw stabs name. */
    private val astsByName: Map<String, List<TypeAst>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget }
            .groupBy { it.name!! }
    }

    /**
     * Secondary index for XRef resolution: base-tag (template args + namespace
     * stripped). Only complete definitions — no point falling back to another
     * forward decl.
     */
    private val astsByBaseTag: Map<String, List<TypeAst>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget && it.body.isComplete }
            .groupBy { QualifiedName.baseTag(it.name!!) }
    }

    private val hashCache: MutableMap<GlobalTypeId, Int> by lazy {
        // Pre-warm by hashing every typeAst body with an empty visited set so
        // cache state doesn't bias collision classification. Same cache is
        // reused for divergentCollisions filtering and for downstream
        // contentHash queries.
        mutableMapOf<GlobalTypeId, Int>().also { c ->
            for (ast in typeAsts.values) c[ast.id] = ast.body.contentHash(this, c)
        }
    }

    override fun byId(id: GlobalTypeId): TypeAst? = typeAsts[id]

    /** Convenience: id → struct body (null if not a struct). */
    fun getStruct(id: GlobalTypeId): TypeDecl.Struct<GlobalTypeId>? = typeAsts[id]?.body as? TypeDecl.Struct

    override fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>): TypeAst? =
        (lookupByXRef(xref, recordDegradation = false) as? XRefLookup.Resolved)?.ast

    /**
     * Outcome of an XRef lookup. [Resolved] carries the canonical [TypeAst];
     * [Unresolved] carries a [reason] distinguishing benign "no candidate"
     * forward decls from real resolver gaps (kind mismatch, ambiguous size).
     */
    sealed interface XRefLookup {
        data class Resolved(val ast: TypeAst) : XRefLookup
        data class Unresolved(val reason: Reason, val diagnosis: String) : XRefLookup

        enum class Reason { NoCandidate, KindMismatch, AmbiguousSize }
    }

    /**
     * Resolve [xref] to its canonical [TypeAst].
     *
     * Tries exact-name lookup first, then base-tag fallback (used for the
     * "bare forward decl in one CU vs full template instantiation in another"
     * case). When [recordDegradation] is true (the materialiser path), an
     * `xref-undefined` / `xref-kind-mismatch` / `xref-ambiguous` event is
     * recorded at the failure site. When false (the contentHash oracle path),
     * the lookup runs silently — content hashing legitimately queries
     * unresolvable XRefs while computing the cache.
     */
    fun lookupByXRef(xref: TypeDecl.XRef<GlobalTypeId>, recordDegradation: Boolean = true): XRefLookup {
        astsByName[xref.tagName]
            ?.firstOrNull { it.body.matchesXRefKind(xref.kind) }
            ?.let { return XRefLookup.Resolved(it) }

        val tag = QualifiedName.baseTag(xref.tagName)
        val sameTagAnyKind = if (tag.isNotEmpty()) astsByBaseTag[tag].orEmpty() else emptyList()
        val sameKind = sameTagAnyKind.filter { it.body.matchesXRefKind(xref.kind) }
        val distinctSizes = sameKind.map { it.body.sizeBytes }.toSet()

        if (sameKind.isNotEmpty() && distinctSizes.size == 1) {
            val resolved = sameKind.first()
            sink.log("xref-base-tag-resolved", "'${xref.tagName}' → '${resolved.nameOrId}'", Level.DEBUG)
            return XRefLookup.Resolved(resolved)
        }

        val exactAnyKind = astsByName[xref.tagName].orEmpty()
        val reason = when {
            sameKind.isNotEmpty() -> XRefLookup.Reason.AmbiguousSize
            sameTagAnyKind.isNotEmpty() || exactAnyKind.isNotEmpty() -> XRefLookup.Reason.KindMismatch
            else -> XRefLookup.Reason.NoCandidate
        }
        if (reason == XRefLookup.Reason.AmbiguousSize) {
            sink.log(
                "xref-base-tag-ambiguous",
                "'${xref.tagName}': ${sameKind.size} candidates with sizes $distinctSizes; refusing fallback",
            )
        }
        val diagnosis = xrefDiagnosis(xref)
        if (recordDegradation) {
            val category = when (reason) {
                XRefLookup.Reason.NoCandidate -> "xref-undefined"
                XRefLookup.Reason.KindMismatch -> "xref-kind-mismatch"
                XRefLookup.Reason.AmbiguousSize -> "xref-ambiguous"
            }
            diagnostics.recordDegradation(
                category,
                xref.tagName,
                "[${xref.kind}] $diagnosis",
            )
        } else {
            sink.log("unresolved-xref", "${xref.tagName} [${xref.kind}] $diagnosis", Level.WARN)
        }
        return XRefLookup.Unresolved(reason, diagnosis)
    }

    /**
     * One-line snapshot of what's in the harvest under [xref]'s exact tag
     * and base tag — used in the unresolved-xref log line.
     */
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

    /**
     * Content-equivalence hash for [body], using the typeAsts + XRef index as
     * oracle and the cache pre-warmed during canonicalization.
     */
    fun contentHash(body: TypeDecl<GlobalTypeId>): Int = body.contentHash(this, hashCache)

    /**
     * Multi-body collisions that survive content-equivalence filtering —
     * the genuinely-divergent ones. Per-name buckets dedupe content-
     * equivalent variants down to a single representative.
     */
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
     * Canonical (CategoryPath, ghidraName) → group mapping. Drives Ghidra
     * slot assignment in TypeRegistry. Built only from registerable bodies
     * (Struct/Enum). Computed lazily; touches [hashCache] for winner selection.
     */
    val byCanonicalKey: Map<GhidraKey, CanonicalGroup> by lazy {
        val byGhidraName = typeAsts.values.groupBy { it.ghidraName }
        val attribution = Attribution(
            commonProjectPrefix = commonProjectPrefix(typeAsts.values.map { it.id.source }),
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
        // Winner: largest body, then fewest unresolved Refs (so the DTM gets
        // the most-resolved variant of CUs that disagree on which gcc-implicit
        // slots they emit), then first by source filename for stability.
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
