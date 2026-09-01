package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.harvest.*
import ghistabs.parse.*

/**
 * The type graph: every harvested [Type] indexed by id, by name and by base tag, plus the xref oracle
 * that resolves one to another and the content hashing [ContentIndex] layers on top.
 *
 * It knows nothing about source files — `id.source` is an opaque key here. Which file a type belongs
 * to is [SourceHints]/[EffectiveSource], which spelling that file renders under is [HarvestIndex],
 * and which Ghidra slot it materializes at is [locateTypes]. All three are built on this; none of
 * them is what the graph *is*.
 */
class TypeGraph(private val harvest: Harvest, sink: DiagnosticSink = DummySink) :
    ContentIndex(),
    DiagnosticSink by sink {
    private val typeAsts get() = harvest.types

    /** Every harvested type. Consumers that need the whole set — the materialize passes, diagnostics,
     *  the dumps — take it from here rather than reaching through [harvest], so the model has one
     *  handle. Per-id lookup is [byId]; per-source is [typesBySource]. */
    val allTypes: Collection<Type> get() = typeAsts.values

    /** All named aggregate / enum ASTs, indexed by raw stabs name. */
    internal val astsByName: Map<String, List<Type>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget }
            .groupBy { it.name!! }
    }

    /**
     * Named primitive typedefs ("unsigned int", "char", …) — not XRefTargets so absent from
     * byCanonicalKey, but stabs gives them names worth exposing as typedef aliases. Grouped by
     * ghidraName for one typedef per logical name.
     */
    val namedPrimitiveTypedefs by lazy {
        typeAsts.values
            .filter { it.name != null && !it.body.isXRefTarget }
            .groupBy { it.ghidraName }
    }

    /** Base-tag (template args + namespace stripped) → complete definitions only. */
    private val astsByBaseTag: Map<String, List<Type>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget && it.body.isComplete }
            .groupBy { baseTag(it.name!!) }
    }

    // Pre-warm with empty `visited` so collision classification isn't biased by traversal order.
    // Must stay below astsByName/astsByBaseTag: contentHash resolves xrefs through them, and a `by
    // lazy` delegate field is only assigned when construction reaches its declaration — an init block
    // placed above them reads a still-null delegate (NPE, silently swallowed under CONCURRENT analysis).
    init {
        for ((_, id, _, body) in typeAsts.values) contentCache[id] = content(body)
    }

    override fun byId(id: GlobalTypeId): Type? = typeAsts[id]

    /**
     * Resolve [xref] to its canonical [Type]. Tries exact-name, then base-tag fallback
     * (commits only when all same-kind candidates agree on size). On miss bumps
     * `xref-undefined` / `xref-kind-mismatch` / `xref-ambiguous`. [silent] is for the
     * contentHash oracle path which expects misses.
     */
    override fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>, silent: Boolean): Type? {
        astsByName[xref.tagName]
            ?.firstOrNull { it.body.matchesXRefKind(xref.kind) }
            ?.let { return it }

        val tag = baseTag(xref.tagName)
        val sameTagAnyKind = if (tag.isNotEmpty()) astsByBaseTag[tag].orEmpty() else emptyList()
        val sameKind = sameTagAnyKind.filter { it.body.matchesXRefKind(xref.kind) }
        val distinctSizes = sameKind.map { it.body.sizeBytes }.toSet()

        if (sameKind.isNotEmpty() && distinctSizes.size == 1) {
            val resolved = sameKind.first()
            // Counted on the reporting path only. [silent] is the contentHash oracle, which probes the
            // same xrefs repeatedly; counting probes would make this move with any caching change
            // instead of with the program.
            if (!silent) debug("xref-base-tag-resolved", "'${xref.tagName}' → '${resolved.ghidraName}'")
            return resolved
        }

        if (silent) return null

        val exactAnyKind = astsByName[xref.tagName].orEmpty()
        when {
            sameKind.isNotEmpty() -> {
                debug(
                    "xref-base-tag-ambiguous",
                    "'${xref.tagName}': ${sameKind.size} candidates with sizes $distinctSizes; refusing fallback",
                )
                debug("xref-ambiguous")
            }

            sameTagAnyKind.isNotEmpty() || exactAnyKind.isNotEmpty() -> debug("xref-kind-mismatch")

            else -> debug("xref-undefined")
        }
        debug("unresolved-xref", "${xref.tagName} [${xref.kind}] ${xrefDiagnosis(xref)}")
        return null
    }

    // Silent: this is materializeTopLevel's routing probe. On a miss it falls through to
    // materializeBody's XRef case, which is the authoritative counter — counting here too would
    // tally the same unresolved xref twice.
    fun byXRef(ast: Type): Type? = (ast.body as? TypeDecl.XRef)?.let { xref ->
        byXRef(xref, silent = true)
    }

    /** One-line snapshot of harvest contents under [xref]'s exact tag and base tag. */
    private fun xrefDiagnosis(xref: TypeDecl.XRef<GlobalTypeId>): String {
        val tag = baseTag(xref.tagName)
        val exact = astsByName[xref.tagName].orEmpty()
        val byBase = astsByBaseTag[tag].orEmpty()
        fun summarise(asts: List<Type>): String {
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

    /** Multi-body collisions after content-equivalence filtering — only genuinely divergent ones. */
    val divergentCollisions: Map<GlobalTypeId, Map<String, Set<GlobalTypeDecl>>> by lazy {
        harvest.rawCollisions.filterValues { byName ->
            byName.values.flatten().groupBy(::content).size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                types.groupBy(::content).values.map { it.first() }.toSet()
            }
        }
    }

    /**
     * walks [decl] through `Ref`/`XRef`/`InlineDef` indirection and cv-wrappers to the first body
     * [pick] accepts, or null. `Pointer`/`Reference` are terminals: `Foo *` does not name a `Foo`.
     *
     * An `InlineDef` tries the ast registered at its id before the body spliced in at the use site,
     * which is frequently itself a forward `XRef` — without the preference, polymorphism detection
     * misses inherited vfptrs (`Cat` → `InlineDef(Animal id, XRef body)`) — and falls back to that
     * body when the id leads nowhere, without which a base whose id no CU defined reads as no base.
     */
    fun <R : Any> resolveWith(
        decl: GlobalTypeDecl,
        visited: MutableSet<GlobalTypeId> = mutableSetOf(),
        pick: (GlobalTypeDecl) -> R?,
    ): R? {
        pick(decl)?.let { return it }
        fun step(next: GlobalTypeDecl?) = next?.let { resolveWith(it, visited, pick) }
        fun stepId(id: GlobalTypeId) = if (visited.add(id)) step(byId(id)?.body) else null
        return when (decl) {
            is TypeDecl.Ref -> stepId(decl.id)
            is TypeDecl.XRef -> byXRef(decl)?.takeIf { visited.add(it.id) }?.let { step(it.body) }
            is TypeDecl.InlineDef -> stepId(decl.id) ?: step(decl.inner)
            is TypeDecl.Const -> step(decl.inner)
            is TypeDecl.Volatile -> step(decl.inner)
            is TypeDecl.WithSizeAttr -> step(decl.inner)
            else -> null
        }
    }

    inline fun resolveAny(decl: GlobalTypeDecl, crossinline predicate: (GlobalTypeDecl) -> Boolean) =
        resolveWith(decl) { decl -> predicate(decl).takeIf { it } } == true

    /** The first [T] [decl] names, through the indirection [resolveWith] walks. */
    inline fun <reified T : GlobalTypeDecl> resolve(decl: GlobalTypeDecl): T? = resolveWith(decl) { it as? T }
}
