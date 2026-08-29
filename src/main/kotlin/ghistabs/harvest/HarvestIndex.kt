package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.*

/**
 * Random access over a [Harvest]. Everything downstream reads the stabs through here rather than
 * through [Harvest]'s raw maps, so a type has one identity, one source and one location.
 *
 * What it owns: the id/xref oracle ([byId], [byXRef], and [resolveWith]'s walk over them) backing
 * [ContentIndex]; §15 source folding, which collapses two gcc spellings of one physical header; the
 * per-source views the render iterates; and the decl-level conflict sets.
 *
 * What it delegates: attribution to [EffectiveSource] (which file a type belongs to) and slot
 * assignment to [locateTypes] (which Ghidra location it materializes at). Both need this index
 * to answer, and neither is what indexing *is*.
 */
class HarvestIndex(val harvest: Harvest, private val foldSources: Boolean = true, sink: DiagnosticSink = DummySink) :
    ContentIndex(),
    DiagnosticSink by sink {
    private val typeAsts get() = harvest.types

    /** Every harvested type. Consumers that need the whole set — the materialize passes, diagnostics,
     *  the dumps — take it from here rather than reaching through [harvest], so the model has one
     *  handle. Per-id lookup is [byId]; per-source is [typesBySource]. */
    val allTypes: Collection<Type> get() = typeAsts.values

    /**
     * Every source spelling the stabs mention, however they mention it: a file that was inlined from,
     * a file that holds statics, and a type's own `N_SOL` or CU. `image.h` is in none of the first
     * two — nothing was inlined from it and it declares no statics — and is known only as some type's
     * `id.source`.
     */
    val allSources by lazy {
        harvest.lineEntries.keys + harvest.staticsByCu.keys +
            typeAsts.values.flatMap { listOfNotNull(it.sourceFile, it.id.source.identity) }
    }

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

    /** Where the stabs say a type lives, before any source root. */
    val sourceHints = SourceHints(this)

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
        val counter = when {
            sameKind.isNotEmpty() -> {
                debug(
                    "xref-base-tag-ambiguous",
                    "'${xref.tagName}': ${sameKind.size} candidates with sizes $distinctSizes; refusing fallback",
                )
                "xref-ambiguous"
            }

            sameTagAnyKind.isNotEmpty() || exactAnyKind.isNotEmpty() -> "xref-kind-mismatch"

            else -> "xref-undefined"
        }
        debug(counter)
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
     * Canonical (category, ghidraName) → group; drives TypeRegistry slot assignment. XRef-targets are
     * bucketed into `(category, ghidraName)` slots ([classifyGroup] picks each winner), then slots are
     * unified by **content hash** (§20): gcc spells one header two ways, so one logical type lands in
     * several slots (named, anonymous copy, typedef aliases) → several DataTypes → the decompiler picks
     * the wrong same-named one. Within a content class holding exactly one named ghidraName, every slot —
     * anonymous ones included — collapses onto that name's largest slot. Content, not path, is the signal,
     * so it reaches headers that don't fold by basename; distinct-named or unnamed classes stay separate.
     */
    val byLocation: Map<TypeLocation, LocatedType> by lazy {
        locateTypes(
            Attribution(
                commonProjectPrefix = commonProjectPrefix(typeAsts.values.map { it.id.source }),
                multiSourceHeaderHints = sourceHints.multiSourceHeaderHints,
            ),
        )
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

    // ── §15 source folds (private mechanism): two gcc spellings of one physical header → one output
    // file. Render never sees these — only the folded per-source views in the facade below. ──
    val sourceFolds: Map<GhidraSourceFile, GhidraSourceFile> by lazy { foldSourcePaths(allSources) }

    /**
     * A raw spelling's render identity: its basename fold (§15), then its compilation directory where
     * gcc gave it one. [foldSources] off → bypass, so `sourceFolds` is never computed.
     *
     * The directory half was `locate()`, applied at the moment a file was written; a source that
     * *is* an identity carries where it lives instead, so nothing downstream has to reconstruct it.
     */
    internal fun fold(source: GhidraSourceFile) =
        (if (foldSources) sourceFolds[source] ?: source else source).let { cuDirectories[it] ?: it }

    fun LineEntry.folded() = copy(source = fold(source))
    fun <S : SymbolDecl<GlobalTypeId>> Symbol<S>.folded() = copy(sourceFile = fold(sourceFile))

    // Blocks carry a source too, and it was the one field left raw — so `inlineParams`, which asks
    // whether a block belongs to the file being rendered, compared a raw N_SOL spelling against a
    // folded one. It matched only while the fold happened to pick the bare spelling N_SOL usually
    // uses; folding onto the full path exposed it, and every pseudo-call in xvimage.cpp lost its
    // parameter names to the dataflow fallback.
    private fun BlockScope.folded(): BlockScope = copy(
        source = source?.let(::fold),
        locals = locals.map { it.folded() },
        children = children.map { it.folded() },
    )

    // ── Render facade: per-source views with every source spelling already folded (§15). ──

    /**
     * Every spelling the stabs mention → the identity it renders as. `SourceMapApplier` registers
     * both sides, so the program ends up listing every file it was built from — including headers
     * that carry no line entry and no symbol, which are still files this binary was built from and
     * which the render draws types in.
     *
     * The line map is published under the raw spellings and then folded with
     * `transferSourceMapEntries`, so a folded-away spelling stays listed with zero entries: honest
     * about what gcc emitted, while the entries sit on the identity the render reads them back by.
     */
    val renderIdentityBySource: Map<GhidraSourceFile, GhidraSourceFile> by lazy {
        allSources.associateWith(::fold)
    }

    /**
     * The sources gcc compiled as a translation unit — an `N_SO` of its own — as against the files it
     * only ever included. Every stab record carries which of the two it came from ([SourceFile]); the
     * render had been asking "does this file define functions", which is a different question and
     * answers wrong for a header full of inline methods.
     */
    val compilationUnits: Set<GhidraSourceFile> by lazy {
        (harvest.functions.map { it.cu } + typeAsts.values.map { it.id.source })
            .filterIsInstance<SourceFile.CUSource>()
            .map { it.identity }
            .plus(harvest.staticsByCu.keys)
            .mapTo(mutableSetOf(), ::fold)
    }

    /**
     * Where a compilation unit lives, keyed by the bare spelling everything else names it by. gcc
     * records it in the leading trailing-slash `N_SO`, and `SourceFile.CUSource` has carried it all
     * along, so `main.cpp` is really `E:/work/cc/devtools/toolchain/vm/tool/main.cpp`
     * and [fold] gives it that identity — where the directory applies at all, which
     * [SourceFile.CUSource.spelling] decides. A header gets no such treatment: gcc gives it no directory
     * of its own, and inferring one from the CU that included it is the inference
     * [resolveAgainstDirectory] refuses for good reason.
     *
     * DTM categories are unaffected — those key off `cu.filename` through [Attribution], not through
     * the render identity, and read better short (`/main.cpp/…`, not `/E:/work/…/main.cpp/…`).
     */
    private val cuDirectories: Map<GhidraSourceFile, GhidraSourceFile> by lazy {
        (harvest.functions.map { it.cu } + typeAsts.values.map { it.id.source })
            .filterIsInstance<SourceFile.CUSource>()
            .mapNotNull { cu -> cu.spelling.takeIf { it != cu.filename }?.let { cu.identity to sourceFileOf(it) } }
            .toMap()
    }

    /** Open functions with their line entries / params / locals folded onto output spellings. */
    val functions: List<Func> by lazy {
        harvest.functions.map { f ->
            f.copy(
                lineEntries = f.lineEntries.map { it.folded() }.toMutableList(),
                params = f.params.map { it.folded() }.toMutableList(),
                locals = f.locals.map { it.folded() }.toMutableList(),
                blocks = f.blocks.map { it.folded() },
            )
        }
    }

    /** A function's source: lowest-address SLINE, else the class-decl source (gcc-implicit methods). */
    fun Func.source() = when {
        isSyntheticInit -> fold(cu.identity)
        else -> lineEntries.minByOrNull { it.addr.offset }?.source
            ?: declaringClassSource()?.let(::fold)
    }

    /**
     * Where the class owning this method is declared. gcc leaves an enclosing *namespace* out of a
     * type's stab name but keeps an enclosing *class* in it (`Outer::Inner`), so no single element of
     * the demangled scope chain is the key: try progressively shorter suffixes, longest first —
     * `std::locale::facet` → `locale::facet` → `facet`.
     */
    private fun Func.declaringClassSource(): GhidraSourceFile? = scopePath()?.let { path ->
        path.indices.firstNotNullOfOrNull { i -> sourceHints.classSourceByName[path.drop(i).joinToString("::")] }
    }

    /** Functions per source — the inverted view render needs, matching [linesBySource]/[staticsBySource]
     *  rather than making every caller scan the whole function list once per rendered file. */
    val functionsBySource: Map<GhidraSourceFile, List<Func>> by lazy {
        functions.mapNotNull { f -> f.source()?.let { it to f } }.groupBy({ it.first }, { it.second })
    }

    /** Functions by linkage name — the lookup `renderFull` needs to attach a real signature to a
     *  method stab, built once rather than per rendered struct. */
    val functionsByMangledName: Map<String, Func> by lazy { functions.associateBy { it.name } }
}
