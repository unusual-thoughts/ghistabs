package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.harvest.*
import ghistabs.materialize.itanium.Itanium
import ghistabs.parse.*

/**
 * Which file each harvested type *and function* is attributed to, once a source root has had its say
 * — the question `effectiveSourceFor` answers and every per-source view is grouped by.
 *
 * [SourceHints] is the floor: what gcc recorded, overridden by where a class's methods were compiled.
 * [declarers] outranks both and is the only evidence that reads real source text — defined by the
 * render once a source root has resolved files (§46), and absent otherwise, which leaves attribution
 * exactly as the hints left it.
 *
 * [Func.source] and [functionsBySource] live here rather than on [SourceIndex] because "which file
 * does this belong to" is this class's question whichever kind of symbol asks it. They sat with the
 * fold only because they need it, and that is a call, not a kinship — it was also the one thing
 * making the fold depend on attribution.
 */
class EffectiveSource(private val index: HarvestIndex, val declarers: (Type.Decl) -> GhidraSourceFile?) :
    DiagnosticSink by index {
    private val hints: SourceHints = index.hints
    private val sources = index.sources

    private fun declarerOf(type: Type) = type.declKey()?.let { declarers(it) }

    /** A function's source: lowest-address SLINE, else the class-decl source (gcc-implicit methods). */
    fun Func.source() = when {
        isSyntheticInit -> sources.fold(cu.identity)
        else -> lineEntries.minByOrNull { it.addr.offset }?.source
            ?: declaringClassSource()?.let(sources::fold)
    }

    /**
     * Where the class owning this method is declared. gcc leaves an enclosing *namespace* out of a
     * type's stab name but keeps an enclosing *class* in it (`Outer::Inner`), so no single element of
     * the demangled scope chain is the key: try progressively shorter suffixes, longest first —
     * `std::locale::facet` → `locale::facet` → `facet`.
     */
    private fun Func.declaringClassSource(): GhidraSourceFile? = scopePath()?.let { path ->
        path.indices.firstNotNullOfOrNull { i -> hints.classSourceByName[path.drop(i).joinToString("::")] }
    }

    /** Functions per source — the inverted view render needs, matching `linesBySource`/[staticsBySource]
     *  rather than making every caller scan the whole function list once per rendered file. */
    val functionsBySource: Map<GhidraSourceFile, List<Func>> by lazy {
        sources.functions.mapNotNull { f -> f.source()?.let { it to f } }.groupBy({ it.first }, { it.second })
    }

    /**
     * The real source first, then the hint, then what gcc recorded.
     *
     * The plan had the hint first, on the reasoning that its vote follows method bodies and is
     * therefore code rather than inference. Measured on a gcc 3.2.3 PE, the two disagree
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
        val hint = hints.hintedFor(this)
        val recorded = hints.recordedFor(this)
        val declared = declarerOf(this)
        val chosen = declared ?: hint ?: recorded
        // Said per decision, because "the root moved n declarations" is the whole measurement of a
        // phase that changes attribution — and because the root overruling a hint is the one case
        // where two mechanisms with evidence disagree, which is worth being able to count.
        when {
            declared == null -> Unit
            hint != null && hint != declared ->
                debug("source-root-over-hint", "$name L$line: $declared over $hint")
            chosen != recorded -> debug("source-root-refiled", "$name L$line: $recorded → $chosen")
            else -> debug("source-root-confirms", "$name L$line: $chosen")
        }
        return chosen
    }

    // Keyed by id, not by Type: Type is a data class holding the whole TypeDecl body, so a Type-keyed
    // map deep-hashes an entire type tree on every lookup — and this is looked up once per type per
    // rendered source. GlobalTypeId is (source, n).
    private val effectiveSources = lazy { index.types.allTypes.associate { it.id to it.effectiveSource() } }
    private val effectiveSourceById: Map<GlobalTypeId, GhidraSourceFile> by effectiveSources

    /** Type → its rendering source (§15) — render's sole type-attribution accessor. */
    fun effectiveSourceFor(type: Type) = effectiveSourceById[type.id] ?: type.effectiveSource()

    /** Anonymous aggregates per effective source, deduped by ghidraName (which the §20 content merge
     *  already collapsed) and sorted by it — every CU emits its own copy of each anonymous type. */
    val anonAggregates by lazy {
        index.types.allTypes
            .filter { it.name.isNullOrEmpty() && it.body.isXRefTarget }
            .groupBy { effectiveSourceFor(it) }
            .mapValues { (_, asts) -> asts.distinctBy { it.ghidraName }.sortedBy { it.ghidraName } }
    }

    /**
     * Class name → the file its declaration *renders* in, which is where anything gcc dated by that
     * declaration belongs. Not [classSourceByName], which answers the neighbouring question — the file
     * the type id itself belongs to — and puts `Image` in main.cpp, the first CU that defined it,
     * while the render draws `class Image` in image.h. Concrete bodies only: an `XRef` forward-decl
     * stub names whichever unrelated header mentioned the class by pointer.
     */
    internal val classRenderSourceByName: Map<String, GhidraSourceFile> by lazy {
        index.types.allTypes
            .filter { it.body is TypeDecl.Struct || it.body is TypeDecl.Enum }
            .mapNotNull { t -> t.name?.let { it to effectiveSourceFor(t) } }
            .toMap()
    }

    /** Declared types per source, same inversion as [functionsBySource]. */
    val typesBySource: Map<GhidraSourceFile, List<Type>> by lazy { index.types.allTypes.groupBy(::effectiveSourceFor) }

    /**
     * The same before the source root is consulted — what decides whether a local file is the one
     * this binary was built from ([ghistabs.importer.LocalSources]), and the reason that check
     * cannot recurse into the attribution it goes on to feed.
     */
    val baseTypesBySource: Map<GhidraSourceFile, List<Type>> by lazy {
        index.types.allTypes.groupBy(hints::baseSourceOf)
    }

    private val templateDecls get() = index.types.allTypes.filter { it.name?.contains('<') == true }

    private val typedefDecls get() = index.types.allTypes.filter {
        it.body !is TypeDecl.Struct &&
            it.body !is TypeDecl.Enum
    }

    /**
     * Both sets as they stand before the source root — the declarations the root's own agreement
     * guard must not be judged on, since at most one of their claimants is right and holding a
     * correct local file to them scored it 0 of 17 (§ phase 3). One set, not two: the guard only ever
     * removes evidence with it, and the reason the two are counted apart is a placement rule the
     * guard has no part in.
     */
    val baseConflictedDecls: Set<Type.Decl> by lazy {
        conflictsAmong(templateDecls, hints::baseSourceOf) +
            conflictsAmong(typedefDecls, hints::baseSourceOf)
    }

    /**
     * `(name, line)` pairs that end up filed under more than one source — so at most one of them
     * is where the declaration sits, and nothing here says which.
     *
     * A declaration has one site. `_Alloc_traits<…>` arrives as eight instantiations all carrying
     * line 898, spread across image.h, vminfo.h, xvimage.h and three CUs: they cannot all be
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
     * Where a `_ZTI<class>` typeinfo object belongs: with its class, not with the CU that happened to
     * emit it.
     *
     * gcc drops the file of every deferred file-scope static — `dbxout_prepare_symbol` emits the
     * symbol's own `N_SOL` only under `WINNING_GDB` — so these arrive filed under whatever CU was
     * last in effect. The *line* survives, and for a typeinfo object it is the class's own declaration
     * line: `_ZTI5Image` is L29 in every CU that emits it, and `class Image` is image.h L29. (Its
     * sibling `_ZTS` string is not the same case — one PE fixture gives one class five different lines
     * across five CUs — so nothing about those is worth trusting but the address.)
     */
    private fun SymbolDecl.Static<*>.typeinfoSource() = name
        .let(Itanium::typeinfoClassOf)
        ?.let { classRenderSourceByName[it] }

    /** File-scope symbols per source — by CU, except where the symbol itself names a better one. */
    val staticsBySource: Map<GhidraSourceFile, List<StaticSymbol>> by lazy {
        index.harvest.sources.entries.flatMap { (cu, harvested) ->
            harvested.cu?.statics.orEmpty().map {
                with(sources) { (it.body.typeinfoSource() ?: fold(cu)) to it.folded() }
            }
        }.groupBy({ it.first }, { it.second })
    }
}

private fun conflictsAmong(asts: Collection<Type>, sourceOf: (Type) -> GhidraSourceFile) = asts
    .groupBy({ it.declKey() }, sourceOf)
    .filterValues { it.distinct().size > 1 }
    .keys
    .filterNotNull()
    .toSet()
