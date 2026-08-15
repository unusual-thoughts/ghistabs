package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.materialize.itanium.Itanium
import ghistabs.parse.*

/**
 * Indexes the [Harvest]'s typeAsts: id/xref oracle for [ContentIndex], xref resolution with
 * per-reason failure counters, [byLocation] grouping for TypeRegistry slot assignment,
 * and content-distinct collision filtering.
 */
class HarvestIndex(val harvest: Harvest, private val foldSources: Boolean = true, sink: DiagnosticSink = DummySink) :
    ContentIndex(),
    DiagnosticSink by sink {
    private val typeAsts get() = harvest.types

    /** Every harvested type. Consumers that need the whole set — the materialize passes, diagnostics,
     *  the dumps — take it from here rather than reaching through [harvest], so the model has one
     *  handle. Per-id lookup is [byId]; per-source is [typesBySource]. */
    val allTypes: Collection<Type> get() = typeAsts.values

    /** All named aggregate / enum ASTs, indexed by raw stabs name. */
    private val astsByName: Map<String, List<Type>> by lazy {
        typeAsts.values
            .filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget }
            .groupBy { it.name!! }
    }

    /** Anonymous aggregates per effective source, deduped by ghidraName (which the §20 content merge
     *  already collapsed) and sorted by it — every CU emits its own copy of each anonymous type. */
    val anonAggregates by lazy {
        typeAsts.values
            .filter { it.name.isNullOrEmpty() && it.body.isXRefTarget }
            .groupBy { effectiveSourceFor(it) }
            .mapValues { (_, asts) -> asts.distinctBy { it.ghidraName }.sortedBy { it.ghidraName } }
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

    /** Convenience: id → struct body (null if not a struct). */
    fun getStruct(id: GlobalTypeId): TypeDecl.Struct<GlobalTypeId>? = typeAsts[id]?.body as? TypeDecl.Struct

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
    val divergentCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> by lazy {
        harvest.rawCollisions.filterValues { byName ->
            byName.values.flatten().groupBy(::content).size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                types.groupBy(::content).values.map { it.first() }.toSet()
            }
        }
    }

    // ── §15 source folds (private mechanism): two gcc spellings of one physical header → one output
    // file. Render never sees these — only the folded per-source views in the facade below. ──
    val sourceFolds: Map<GhidraSourceFile, GhidraSourceFile> by lazy {
        foldSourcePaths(
            harvest.lineEntries.keys + harvest.staticsByCu.keys +
                typeAsts.values.flatMap { listOfNotNull(it.declSourceFile, it.id.source.identity) },
        )
    }

    /**
     * A raw spelling's render identity: its basename fold (§15), then its compilation directory where
     * gcc gave it one. [foldSources] off → bypass, so `sourceFolds` is never computed.
     *
     * The directory half was `locate()`, applied at the moment a file was written; a source that
     * *is* an identity carries where it lives instead, so nothing downstream has to reconstruct it.
     */
    private fun fold(source: GhidraSourceFile) =
        (if (foldSources) sourceFolds[source] ?: source else source).let { cuDirectories[it] ?: it }

    private fun LineEntry.folded() = copy(source = fold(source))
    private fun <S : SymbolDecl<GlobalTypeId>> Symbol<S>.folded() = copy(sourceFile = sourceFile?.let(::fold))

    // Blocks carry a source too, and it was the one field left raw — so `inlineParams`, which asks
    // whether a block belongs to the file being rendered, compared a raw N_SOL spelling against a
    // folded one. It matched only while the fold happened to pick the bare spelling N_SOL usually
    // uses; folding onto the full path exposed it, and every pseudo-call in file.cpp lost its
    // parameter names to the dataflow fallback.
    private fun BlockScope.folded(): BlockScope = copy(
        source = source?.let(::fold),
        locals = locals.map { it.folded() },
        children = children.map { it.folded() },
    )

    // name → its defining source. Prefer concrete Struct/Enum over forward-decl XRef stubs: gcc emits
    // those for classes merely mentioned by pointer in unrelated headers (e.g. reachable via <iostream>),
    // and picking one would route the class's methods to that header instead of its real home.
    private val classSourceByName: Map<String, GhidraSourceFile> by lazy {
        buildMap {
            val bestRank = mutableMapOf<String, Int>()
            for ((_, id, name, body) in typeAsts.values) {
                val n = name ?: continue
                val rank = when (body) {
                    is TypeDecl.Struct, is TypeDecl.Enum -> 2
                    is TypeDecl.XRef -> 0
                    else -> 1
                }
                if (rank > (bestRank[n] ?: -1)) {
                    bestRank[n] = rank
                    put(n, id.source.identity)
                }
            }
        }
    }

    /**
     * Infer a class's owning header when gcc emitted its `:Tt` definition inside a .cpp, losing the header
     * association so `id.source` is a misleading .cpp (e.g. AppImage's def lands only in main.cpp). Majority
     * vote over the N_SOL source of line entries inside the type's member bodies: gcc emits `N_SOL("foo.h")`
     * bursts wherever a method inlines header code, pointing back at the real header. A real (non-stdlib)
     * header wins; a stdlib-only type falls back to the stdlib majority only when its def is scattered across
     * CUs (collapse it, rather than drag a single CU-local instantiation into a stdlib header).
     *
     * Voted over **raw** sources (before the §15 fold), so the hint — which feeds `Attribution.keyFor` —
     * keeps DTM attribution independent of render-source folding.
     */
    // Every known header by its stem, so a CU can find the header it is conventionally paired with
    // (`image.cpp` → `image.h`). Ambiguous stems are dropped rather than guessed between.
    private val headersByStem: Map<String, GhidraSourceFile> by lazy {
        // Every source the stabs mention, however it is mentioned. `image.h` appears in none of the
        // line entries — nothing was inlined from it — and in no declSourceFile either; it is known
        // only as some type's `id.source`, which is exactly the case this lookup exists to serve.
        // Spellings of one file collapse (§15 folds them later anyway); genuinely distinct files
        // sharing a stem are dropped rather than guessed between.
        (
            harvest.lineEntries.keys + typeAsts.values.flatMap {
                listOfNotNull(it.declSourceFile, it.id.source.identity)
            }
            )
            .filter { it.filename.hasHeaderExtension() && !it.path.isStdMarkerPath() }
            .groupBy { it.filename.substringBeforeLast('.') }
            .filterValues { v -> v.distinctBy { it.filename }.size == 1 }
            .mapValues { (_, v) -> v.minBy { it.path.length } }
    }

    private val multiSourceHeaderHints: Map<String, GhidraSourceFile> by lazy {
        // An instantiation with no method evidence of its own — `_Vector_alloc_base<unsigned short>`
        // declares three pointers and no methods — inherits what its siblings' methods established.
        // One template lives in one header, so `_Vector_alloc_base<Exclusion>` answers for it.
        val voted = votedHeaderHints
        // Seeded from where instantiations *already* sit as well as from the vote: `allocator<char>`,
        // `<void>` and `<wchar_t>` were never voted on because nothing was wrong with them — gcc put
        // them in stl_alloc.h — and they are exactly what says where `allocator<unsigned short>`
        // belongs. Only stdlib homes seed, and `id.source` rather than the effective source, since
        // this map is what the effective source consults.
        val settled = typeAsts.values
            .mapNotNull { ast -> ast.name?.takeIf { '<' in it }?.let { it to ast.id.source.identity } }
            .filter { (_, home) -> home.path.isStdMarkerPath() }
        val homeByTemplate = (voted.entries.filter { '<' in it.key }.map { it.key to it.value } + settled)
            .groupBy({ it.first.substringBefore('<') }, { it.second })
            .mapValues { (_, homes) -> homes.groupingBy { it }.eachCount().maxByOrNull { it.value }!!.key }
        val bySibling = voted + astsByName.keys
            .filter { '<' in it && it !in voted }
            .mapNotNull { name -> homeByTemplate[name.substringBefore('<')]?.let { name to it } }
        // Last resort, and it is structural rather than evidential: a base class inherits where its
        // derived class went. Bases only — extending it to field types moved nothing on the corpus. `_Vector_alloc_base<unsigned short>` declares three pointers, has no
        // methods, and no instantiation of *that* template anywhere in the corpus has an out-of-line
        // method — so neither the vote nor the sibling pass can reach it. What is known is that
        // `_Vector_base<unsigned short>`, which derives from it, lives in stl_vector.h. Chains run
        // `vector` → `_Vector_base` → `_Vector_alloc_base`, hence the rounds; templates only, so a
        // project class can never be dragged along by a base it shares with the standard library.
        (1..3).fold(bySibling) { homes, _ ->
            homes + typeAsts.values
                .flatMap { ast ->
                    val home = ast.name?.let { homes[it] } ?: return@flatMap emptyList()
                    (ast.body as? TypeDecl.Struct)?.bases.orEmpty().mapNotNull { base ->
                        (base.type as? TypeDecl.Ref)?.id?.let { byId(it) }?.name
                            ?.takeIf { '<' in it && it !in homes }?.let { it to home }
                    }
                }
        }
    }

    private val votedHeaderHints: Map<String, GhidraSourceFile> by lazy {
        val funcsByMangled = harvest.functions.filter { (it.sizeBytes ?: 0uL) > 0uL }.associateBy { it.name }
        val defSourcesByName = typeAsts.values
            .filter { it.name != null }
            .groupBy({ it.name!! }, { it.id.source.identity })
            .mapValues { it.value.toSet() }
        // Header line-entries sorted by address once, so each method's [lo,hi) range is a binary-searched
        // slice instead of a full scan of every source's entries per method (was O(types × methods ×
        // entries)). Non-header sources never vote, so they're dropped up front.
        val hdrEntries = harvest.lineEntries.entries
            .filter { it.key.filename.hasHeaderExtension() }
            .flatMap { (src, entries) ->
                val std = src.path.isStdMarkerPath()
                entries.map { Triple(it.addr.offset, src, std) }
            }
            .sortedBy { it.first }
        val hdrOffsets = LongArray(hdrEntries.size) { hdrEntries[it].first }

        buildMap {
            for ((name, asts) in astsByName) {
                val defSources = defSourcesByName[name] ?: continue
                // A template instantiation is the one thing gcc files by accident: it emits
                // `vector<unsigned short>` inside whichever header first needed it, so image.h — a
                // header, hence already past this guard — collected 31 rows of libstdc++. Everything
                // else declared only in headers is left alone, which also bounds what this loop costs.
                val templated = '<' in name
                if (!templated && defSources.all { it.filename.hasHeaderExtension() }) continue
                val methods = asts.flatMap { (it.body as? TypeDecl.Struct<*>)?.methods.orEmpty() }
                if (methods.isEmpty()) continue
                // A type's own def sources win by body size, so exclude them from the vote.
                val userVote = mutableMapOf<GhidraSourceFile, Int>()
                val stdVote = mutableMapOf<GhidraSourceFile, Int>()
                for (m in methods) {
                    val func = funcsByMangled[m.mangled ?: continue] ?: continue
                    val lo = func.addr.offset
                    val hi = lo + (func.sizeBytes ?: 0uL).toLong()
                    var i = hdrOffsets.lowerBound(lo)
                    while (i < hdrEntries.size && hdrOffsets[i] < hi) {
                        val (_, src, isStd) = hdrEntries[i++]
                        if (src !in defSources) (if (isStd) stdVote else userVote).merge(src, 1, Int::plus)
                    }
                }
                // With no user header in the vote, the CU that defines the methods names one by
                // convention. A class whose methods are all out-of-line contributes no N_SLINE of its
                // own — nothing was ever inlined from its header — so it can never appear in the vote,
                // and the stdlib fallback claimed it: `class Image` was declared in stl_vector.h,
                // while image.h rendered 903 rows of nothing but vector<unsigned short>. The guard
                // below is `defSources.size > 1`, true of any class defined across several CUs, so it
                // never caught this. bouniaf escaped only because 2 lines happened to inline from
                // header.h.
                val siblingHeader = methods.asSequence()
                    .mapNotNull { m -> funcsByMangled[m.mangled]?.cu }
                    .distinct().singleOrNull()
                    ?.let { cu -> headersByStem[cu.identity.filename.substringBeforeLast('.')] }
                val user = userVote.maxByOrNull { it.value }?.key
                val std = stdVote.maxByOrNull { it.value }?.key
                // An instantiation follows its code: with no user header voting, the stdlib headers
                // its methods' bodies live in are what say where it came from, and its sibling header
                // is just the CU that happened to need it. A plain class is the other way round —
                // `class Image` is stabs-declared in stl_vector.h and belongs to image.h, which is
                // what `siblingHeader` recovers and what the stdlib vote would get wrong.
                val winner = when {
                    templated -> user ?: std ?: siblingHeader
                    else -> user ?: siblingHeader ?: std?.takeIf { defSources.size > 1 }
                }
                winner?.let { put(name, it) }
            }
        }
    }

    /** First index into a sorted [LongArray] whose value is `>= target` (binary lower-bound). */
    private fun LongArray.lowerBound(target: Long): Int {
        var lo = 0
        var hi = size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (this[mid] < target) lo = mid + 1 else hi = mid
        }
        return lo
    }

    // Named types vote via the hint (member-SLINE header); typedefs trust their N_SOL declSourceFile (a
    // template-instantiation typedef splayed into a CU still names its real header); structs/enums fall
    // back to id.source (their `:T` body is legitimately CU-emitted, §6).
    private fun Type.hinted() = name?.let { multiSourceHeaderHints[it] }

    private fun Type.recorded() =
        declSourceFile?.takeIf { body !is TypeDecl.Struct && body !is TypeDecl.Enum } ?: id.source.identity

    /** Attribution before a source root has a say. */
    private fun Type.baseSource() = fold(hinted() ?: recorded())

    /**
     * The real source first, then the hint, then what gcc recorded.
     *
     * The plan had the hint first, on the reasoning that its vote follows method bodies and is
     * therefore code rather than inference. Measured on unbouniaf against 3.2.3, the two disagree
     * **three times**, all of them `_Vector_alloc_base<…>` at L79, and stl_vector.h L79 reads
     * `class _Vector_alloc_base {` while the hint says stl_iterator.h and stl_algobase.h — headers
     * whose only claim is that the instantiation's methods were compiled there. A definition at the
     * line beats a vote about where the code went.
     *
     * That holds only because a *forward* declaration is not a declaration site here: with
     * `class allocator;` counted, `stringfwd.h` L49 outranked `stl_alloc.h`, where the class is, and
     * the hint was the one that was right (see `Scan.TAG`).
     */
    private fun Type.effectiveSource(): GhidraSourceFile {
        val hint = hinted()?.let(::fold)
        val declared = declarerOf(this)
        val chosen = declared ?: hint ?: fold(recorded())
        // Said per decision, because "the root moved n declarations" is the whole measurement of a
        // phase that changes attribution — and because the root overruling a hint is the one case
        // where two mechanisms with evidence disagree, which is worth being able to count.
        when {
            declared == null -> Unit
            hint != null && hint != declared ->
                debug("source-root-over-hint", "$name L$declLine: $declared over $hint")
            chosen != fold(
                recorded(),
            ) -> debug("source-root-refiled", "$name L$declLine: ${fold(recorded())} → $chosen")
            else -> debug("source-root-confirms", "$name L$declLine: $chosen")
        }
        return chosen
    }

    /**
     * Which file the local sources say declares `(name, line)` — installed by the render once a
     * source root has resolved files (§46), and answering null everywhere without one, which is what
     * leaves attribution exactly as it was.
     *
     * It must be in place before anything reads attribution, because the per-source views memoise;
     * assigning after that is a silently-ignored root, so it is refused instead.
     */
    var declarers: ((Type.Decl) -> GhidraSourceFile?)? = null
        set(value) {
            check(!effectiveSources.isInitialized()) { "a source root must be installed before attribution is read" }
            field = value
        }

    private fun declarerOf(type: Type) = type.declKey()?.let { declarers?.invoke(it) }

    // Keyed by id, not by Type: Type is a data class holding the whole TypeDecl body, so a Type-keyed
    // map deep-hashes an entire type tree on every lookup — and this is looked up once per type per
    // rendered source. GlobalTypeId is (source, n).
    private val effectiveSources = lazy { typeAsts.values.associate { it.id to it.effectiveSource() } }
    private val effectiveSourceById: Map<GlobalTypeId, GhidraSourceFile> by effectiveSources

    // ── Render facade: per-source views with every source spelling already folded (§15). ──

    /**
     * Every spelling a line entry was filed under → the identity it renders as. The program's line map
     * is published under the raw spellings and then folded with `transferSourceMapEntries`, so the
     * folded-away spelling stays listed with zero entries: honest about what gcc emitted, while the
     * entries sit on the identity the render reads them back by.
     */
    val renderIdentityBySource: Map<GhidraSourceFile, GhidraSourceFile> by lazy {
        harvest.lineEntries.keys.associateWith(::fold)
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
     * along, so `main.cpp` is really `E:/work/cc/devtools/devtools-bouniaf-7-0/vm/project/main.cpp`
     * and [fold] gives it that identity. A header gets no such treatment: gcc gives it no directory
     * of its own, and inferring one from the CU that included it is the inference
     * [resolveAgainstDirectory] refuses for good reason.
     *
     * DTM categories are unaffected — those key off `cu.filename` through [Attribution], not through
     * the render identity, and read better short (`/main.cpp/…`, not `/E:/work/…/main.cpp/…`).
     */
    private val cuDirectories: Map<GhidraSourceFile, GhidraSourceFile> by lazy {
        (harvest.functions.map { it.cu } + typeAsts.values.map { it.id.source })
            .filterIsInstance<SourceFile.CUSource>()
            .mapNotNull { cu -> cu.directory?.let { cu.identity to sourceFileOf(it + cu.filename) } }
            .toMap()
    }

    /** File-scope symbols per source — by CU, except where the symbol itself names a better one. */
    val staticsBySource: Map<GhidraSourceFile, List<StaticSymbol>> by lazy {
        harvest.staticsByCu.entries
            .flatMap { (cu, syms) -> syms.map { (it.body.typeinfoSource() ?: fold(cu)) to it.folded() } }
            .groupBy({ it.first }, { it.second })
    }

    /**
     * Where a `_ZTI<class>` typeinfo object belongs: with its class, not with the CU that happened to
     * emit it.
     *
     * gcc drops the file of every deferred file-scope static — `dbxout_prepare_symbol` emits the
     * symbol's own `N_SOL` only under `WINNING_GDB` — so these arrive filed under whatever CU was
     * last in effect. The *line* survives, and for a typeinfo object it is the class's own declaration
     * line: `_ZTI5Image` is L29 in every CU that emits it, and `class Image` is image.h L29. (Its
     * sibling `_ZTS` string is not the same case — bouniaf gives one class five different lines
     * across five CUs — so nothing about those is worth trusting but the address.)
     */
    private fun SymbolDecl.Static<*>.typeinfoSource() = name
        .let(Itanium::typeinfoClassOf)
        ?.let { classRenderSourceByName[it] }

    /**
     * Class name → the file its declaration *renders* in, which is where anything gcc dated by that
     * declaration belongs. Not [classSourceByName], which answers the neighbouring question — the file
     * the type id itself belongs to — and puts `Image` in main.cpp, the first CU that defined it,
     * while the render draws `class Image` in image.h. Concrete bodies only: an `XRef` forward-decl
     * stub names whichever unrelated header mentioned the class by pointer.
     */
    private val classRenderSourceByName: Map<String, GhidraSourceFile> by lazy {
        typeAsts.values
            .filter { it.body is TypeDecl.Struct || it.body is TypeDecl.Enum }
            .mapNotNull { t -> t.name?.let { it to effectiveSourceFor(t) } }
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
            ?: outermostClass()?.let { classSourceByName[it] }?.let(::fold)
    }

    /** Functions per source — the inverted view render needs, matching [linesBySource]/[staticsBySource]
     *  rather than making every caller scan the whole function list once per rendered file. */
    val functionsBySource: Map<GhidraSourceFile, List<Func>> by lazy {
        functions.mapNotNull { f -> f.source()?.let { it to f } }.groupBy({ it.first }, { it.second })
    }

    /** Functions by linkage name — the lookup `renderFull` needs to attach a real signature to a
     *  method stab, built once rather than per rendered struct. */
    val functionsByMangledName: Map<String, Func> by lazy { functions.associateBy { it.name } }

    /** Declared types per source, same inversion as [functionsBySource]. */
    val typesBySource: Map<GhidraSourceFile, List<Type>> by lazy { typeAsts.values.groupBy(::effectiveSourceFor) }

    /**
     * The same before the source root is consulted — what decides whether a local file is the one
     * this binary was built from ([ghistabs.importer.LocalSources]), and the reason that check
     * cannot recurse into the attribution it goes on to feed.
     */
    val baseTypesBySource: Map<GhidraSourceFile, List<Type>> by lazy { typeAsts.values.groupBy { it.baseSource() } }

    /** Type → its rendering source (§15) — render's sole type-attribution accessor. */
    fun effectiveSourceFor(type: Type) = effectiveSourceById[type.id] ?: type.effectiveSource()

    /**
     * `(name, declLine)` pairs that end up filed under more than one source — so at most one of them
     * is where the declaration sits, and nothing here says which.
     *
     * A declaration has one site. `_Alloc_traits<…>` arrives as eight instantiations all carrying
     * declLine 898, spread across image.h, vminfo.h, header.h and three CUs: they cannot all be
     * right, none of them is (its home is stl_alloc.h, which holds no instantiation of it at all,
     * so no vote or sibling can reach it — §38's grade-3 wall), and rendering it in each of those
     * files at line 898 both states a falsehood and stretches image.h's canvas to 903 rows for 25
     * rows of content. Knowing they are all wrong is enough to stop placing them, which is what the
     * displaced appendix is for.
     *
     * Tags and typedefs are counted separately, and not because it is tidier: `fpos` is a class in
     * fpos.h and a typedef elsewhere, `string` likewise, so one namespace makes them conflict with
     * each other and `class string` loses its place in stringfwd.h to a typedef of the same name.
     */
    val conflictedTemplateDecls: Set<Type.Decl> by lazy {
        conflictsAmong(templateDecls, ::effectiveSourceFor)
    }

    /**
     * The same, for typedefs, where the splaying is gcc's per-instantiation emission: `_Trivial` at
     * L426 in both basic_string.h and stl_uninitialized.h, `_Tag` at L733 in both stl_list.h and
     * stl_uninitialized.h. Only one of each pair is the declaration; the file that reaches the line
     * keeps it.
     */
    val conflictedTypedefDecls: Set<Type.Decl> by lazy {
        conflictsAmong(typedefDecls, ::effectiveSourceFor)
    }

    /**
     * Both sets as they stand before the source root — the declarations the root's own agreement
     * guard must not be judged on, since at most one of their claimants is right and holding a
     * correct local file to them scored it 0 of 17 (§ phase 3). One set, not two: the guard only ever
     * removes evidence with it, and the reason the two are counted apart is a placement rule the
     * guard has no part in.
     */
    val baseConflictedDecls: Set<Type.Decl> by lazy {
        conflictsAmong(templateDecls) { it.baseSource() } + conflictsAmong(typedefDecls) { it.baseSource() }
    }

    private val templateDecls get() = typeAsts.values.filter { it.name?.contains('<') == true }

    private val typedefDecls get() = typeAsts.values.filter { it.body !is TypeDecl.Struct && it.body !is TypeDecl.Enum }

    private fun conflictsAmong(asts: Collection<Type>, sourceOf: (Type) -> GhidraSourceFile) = asts
        .groupBy({ it.declKey() }, sourceOf)
        .filterValues { it.distinct().size > 1 }
        .keys
        .filterNotNull()
        .toSet()

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
        val byGhidraName = typeAsts.values.groupBy { it.ghidraName }
        val attribution = Attribution(
            commonProjectPrefix = commonProjectPrefix(typeAsts.values.map { it.id.source }),
            multiSourceHeaderHints = multiSourceHeaderHints,
        )

        fun headerKey(ast: Type) =
            attribution.keyForAst(ast, byGhidraName.getValue(ast.ghidraName).map { it.id.source }.toSet())

        // Category each C++ class files its own nested members under, keyed by the class's canonicalised
        // stab name. Every method-bearing type contributes its own scope (`basic_string<char,…>` →
        // `/std/string`); method-less nested types below borrow it. Keyed by the stab name (not the
        // demangler leaf, which abbreviates `Ss`→`string`) because that is the spelling a nested type's
        // qualifier or its containing field carries; canonTemplateName erases the whitespace gcc varies.
        val memberCategoryByClass: Map<String, CategoryPath> = buildMap {
            for (ast in typeAsts.values) {
                val path = ast.demangledClassPath() ?: continue
                ast.name?.let { putIfAbsent(canonTemplateName(it), scopeCategory(path)) }
            }
        }

        // Reverse the by-value member edge: nested member type id → the struct that holds it as a field.
        // gcc emits `basic_string<char>::_Alloc_hider` both fully-qualified-with-methods (already
        // scoped) and bare-and-method-less; the bare one is only reachable as `basic_string._M_dataplus`.
        // Drop ids held by two distinct enclosers — no single owning scope.
        val enclosingByNestedId: Map<GlobalTypeId, Type> = buildMap {
            val ambiguous = mutableSetOf<GlobalTypeId>()
            for (ast in typeAsts.values) {
                val struct = ast.body as? TypeDecl.Struct ?: continue
                for (field in struct.fields) {
                    if (field.isStatic) continue
                    val nestedId = byValueStructId(field.type) ?: continue
                    val prev = putIfAbsent(nestedId, ast)
                    if (prev != null && prev.id != ast.id) ambiguous += nestedId
                }
            }
            ambiguous.forEach(::remove)
        }

        fun scopeKey(ast: Type): TypeLocation? {
            // Method-bearing: file under the demangler's namespace category, named by its own leaf — the
            // exact (category, name) Ghidra's this-param class-struct creator uses (same GnuDemangler), so
            // our filled slot IS the slot it would otherwise forge empty. [byLocation] demotes to header
            // only on a genuine content collision within a (scope, leaf). REQUIRES [TypeRegistry.register]
            // to replace Ghidra's empty namespace shadows (REPLACE_EMPTY_STRUCTS) — else `dtm.resolve`
            // keeps the empty shadow at the colliding path and every reference resolves to it (all-undef).
            ast.demangledClassPath()?.let { return TypeLocation(scopeCategory(it.dropLast(1)), it.last()) }

            // Method-less nested member type (`_Alloc_hider`, `_Rep`, `sentry`) — no mangled method to
            // scope it, so it otherwise collides char-vs-wchar under one bare-name header key. Recover the
            // enclosing template from its own `Outer::Inner` stab name, else from the struct that holds it
            // by value, and file it under that template's member category — the slot its qualified,
            // method-bearing sibling already occupies, so the two unify instead of forking a `.conflict`.
            val (enclosingName, leaf) = ast.name?.let(::splitQualified)?.takeIf { it.size > 1 }
                ?.let { it.dropLast(1).joinToString("::") to it.last() }
                ?: enclosingByNestedId[ast.id]?.name?.let { it to ast.ghidraName }
                ?: return null
            return memberCategoryByClass[canonTemplateName(enclosingName)]?.let { TypeLocation(it, leaf) }
        }

        // Scope→header→hash ladder. A type whose enclosing C++ scope is derivable (any member's
        // mangled name yields one) files under that namespace category — matching where Ghidra's
        // this-param class-struct creator looks, so our filled type is the one it reuses instead of
        // synthesizing an empty stub. Header attribution is the fallback for method-less types (C
        // aggregates, gcc anonymous copies) AND the collision-breaker: a scope key holding genuinely
        // divergent content (same (scope,name), several bodies) demotes each body to its header key.
        val slots = typeAsts.values
            .filter { it.body.isXRefTarget }
            .groupBy(::scopeKey)
            .flatMap { (scopeKey, members) ->
                if (scopeKey == null) {
                    members.groupBy { headerKey(it) }.map { (k, ms) -> classifyGroup(k, ms) }
                } else {
                    // Divergence is decided by the scope-owning (method-bearing) members alone. A
                    // method-less nested type recovered into this slot is the same type as its qualified
                    // sibling — layout-identical, differing only in emitted methods, which never enter the
                    // DTM struct — so it rides along and aliases onto the owners' winner instead of forking
                    // the group. Genuine divergence among the owners still demotes every member to header.
                    val owners = members.filter { it.demangledClassPath() != null }.ifEmpty { members }
                    // Layout-only: owners diverge only in per-CU method flags/order (gcc VIRTUAL vs NORMAL,
                    // reordering), which never enter the DTM struct — don't let that noise demote the group.
                    if (owners.groupBy { content(it.body) }.size == 1) {
                        val group = classifyGroup(scopeKey, owners)
                        listOf(if (owners.size == members.size) group else group.copy(members = members.map { it.id }))
                    } else {
                        debug("canonical-scope-collision", "$scopeKey: divergent bodies → demoted to header keys")
                        members.groupBy { headerKey(it) }.map { (k, ms) -> classifyGroup(k, ms) }
                    }
                }
            }

        buildMap {
            // §B: merge by layout, not content — a class's method-less header/`multi` copies share the
            // scope-keyed method-bearing copy's layout (methods never enter the DTM struct), so they fold
            // onto it instead of forking a duplicate slot. The `ghidraName` guard keeps genuinely
            // different same-layout classes apart; the winner prefers the method-bearing copy.
            for (equivalent in slots.groupBy { content(it.type.body) }.values) {
                val named = equivalent.filter { !it.type.name.isNullOrEmpty() }
                if (equivalent.size == 1 || named.map { it.type.ghidraName }.toSet().size != 1) {
                    for (g in equivalent) put(g.location, g)
                    continue
                }
                // Same layout ⇒ same size, so the size tiebreak ties here; the method count decides, which
                // is what makes the scope-keyed method-bearing copy win over a method-less one.
                val winner = named.pickWinner({ it.type.body }, { it.location.toString() })
                debug(
                    "canonical-content-merged",
                    "${winner.location}: ${equivalent.size} groups (${
                        equivalent.count { it.type.name.isNullOrEmpty() }
                    } anon) across ${equivalent.map { it.location.category }.toSet()}",
                )
                put(
                    winner.location,
                    winner.copy(members = equivalent.flatMap { it.members }),
                )
            }
        }
    }

    private fun classifyGroup(key: TypeLocation, members: List<Type>): LocatedType {
        val distinctKinds = members.map { it.body::class }.toSet()
        if (distinctKinds.size > 1) {
            warn("canonical-key-multi-kind", "$key: ${distinctKinds.map { it.simpleName }}")
        }
        val contentClasses = members.groupBy { content(it.body) }.values
        when {
            contentClasses.size > 1 -> debug(
                "canonical-key-multi-hash",
                "$key: ${contentClasses.size} distinct bodies across " +
                    members.map { it.id.source.filename }.toSet(),
            )

            members.size > 1 -> debug(
                "canonical-key-merged",
                "$key: ${members.size} ASTs collapsed (single body)",
            )
        }
        val winner = members.pickWinner({ it.body }, { it.id.source.filename })
        return LocatedType(key, winner, members.map { it.id }, contentClasses.size)
    }

    /**
     * The member whose body best represents the group: largest body → most methods → fewest unresolved
     * Refs → [tiebreak] (stable, and the only criterion that can still tie).
     *
     * Members of a group are one content class, so their layouts — and therefore [TypeDecl.sizeBytes] —
     * are equal and the first criterion ties; the method count is what actually decides. It has to,
     * because methods and static fields are deliberately excluded from [content], so every per-CU copy
     * of a class compares equal however few methods it carries. The winner's body is the one that gets
     * materialized, and ClassBuilder reads its method list for vtable slots, `__thiscall` reparenting
     * and the namespace chain — so a method-poor winner silently loses those. Fewest-unresolved then
     * picks the most-resolved variant when CUs disagree on gcc-implicit slots.
     *
     * Shared by both winner selections (per-key in [classifyGroup], per-content-class in §B): they rank
     * different things — Types vs whole slots — but by one policy, which previously drifted apart.
     */
    private fun <T> List<T>.pickWinner(bodyOf: (T) -> TypeDecl<GlobalTypeId>, tiebreak: (T) -> String) = maxWith(
        compareBy<T> { bodyOf(it).sizeBytes }
            .thenBy { (bodyOf(it) as? TypeDecl.Struct)?.methods?.size ?: 0 }
            .thenByDescending { countUnresolvedRefs(bodyOf(it)) }
            .thenBy(tiebreak),
    )

    private fun countUnresolvedRefs(body: TypeDecl<GlobalTypeId>): Int {
        if (body !is TypeDecl.Struct) return 0
        return body.fields.count { f -> walksToUnresolvedRef(f.type) }
    }

    /** Id of the struct/union [t] embeds by value (through Ref/InlineDef/Const/Volatile only, never a
     *  pointer/array), or null — the containment edge that scopes a method-less nested member type. */
    private tailrec fun byValueStructId(t: TypeDecl<GlobalTypeId>): GlobalTypeId? = when (t) {
        is TypeDecl.Ref -> t.id.takeIf { typeAsts[it]?.body is TypeDecl.Struct }
        is TypeDecl.InlineDef -> if (t.inner is TypeDecl.Struct) t.id else byValueStructId(t.inner)
        is TypeDecl.Const -> byValueStructId(t.inner)
        is TypeDecl.Volatile -> byValueStructId(t.inner)
        else -> null
    }

    private fun walksToUnresolvedRef(t: TypeDecl<GlobalTypeId>): Boolean = when (t) {
        is TypeDecl.Ref -> t.id !in typeAsts
        else -> t.children.any { fields -> fields.any { walksToUnresolvedRef(it) } }
    }

    companion object {
        /** Empty resolver — useful for tests that only need oracle defaults. */
        val Empty = HarvestIndex(Harvest.of(emptyMap()))
    }
}
