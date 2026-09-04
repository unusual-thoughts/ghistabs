package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.harvest.*
import ghistabs.parse.TypeDecl
import ghistabs.parse.canonTemplateName

/**
 * Where the stabs alone say each type lives — attribution before a source root has a say.
 *
 * Two pieces of evidence. What gcc *recorded*: a typedef's `N_SOL` declSourceFile, else the type's
 * own CU. And a *hint* for named types, which outranks it: the header a class's methods were
 * compiled into, voted per line-entry burst over each method's address range, with template
 * instantiations inheriting a sibling instantiation's home and, failing that, their base's.
 *
 * A hint is inference about where code went; [EffectiveSource] layers real source text on top when a
 * root has resolved files. Nothing here reads a file, so this is a pure function of the [Harvest].
 */
class SourceHints(
    val harvest: Harvest,
    val types: TypeGraph,
    val sources: SourceIndex,
    sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    // name → its defining source, keyed canonically so a demangled scope chain can match it (gcc
    // spells stab template args with the spaces the demangler also emits, inconsistently). Prefer
    // concrete Struct/Enum over forward-decl XRef stubs: gcc emits those for classes merely mentioned
    // by pointer in unrelated headers (e.g. reachable via <iostream>), and picking one would route the
    // class's methods to that header instead of its real home.
    internal val classSourceByName: Map<String, GhidraSourceFile> by lazy {
        buildMap {
            val bestRank = mutableMapOf<String, Int>()
            for (ast in types.allTypes) {
                val (id, body) = ast.id to ast.body
                val n = ast.name?.let(::canonTemplateName) ?: continue
                val rank = when (body) {
                    is TypeDecl.Aggregate, is TypeDecl.Enum -> 2
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
        sources.allSources
            .filter { it.filename.hasHeaderExtension() && !it.path.isStdMarkerPath() }
            .groupBy { it.filename.substringBeforeLast('.') }
            .filterValues { v -> v.distinctBy { it.filename }.size == 1 }
            .mapValues { (_, v) -> v.minBy { it.path.length } }
    }

    internal val multiSourceHeaderHints: Map<String, GhidraSourceFile> by lazy {
        // An instantiation with no method evidence of its own — `_Vector_alloc_base<unsigned short>`
        // declares three pointers and no methods — inherits what its siblings' methods established.
        // One template lives in one header, so `_Vector_alloc_base<Exclusion>` answers for it.
        val voted = votedHeaderHints
        // Seeded from where instantiations *already* sit as well as from the vote: `allocator<char>`,
        // `<void>` and `<wchar_t>` were never voted on because nothing was wrong with them — gcc put
        // them in stl_alloc.h — and they are exactly what says where `allocator<unsigned short>`
        // belongs. Only stdlib homes seed, and `id.source` rather than the effective source, since
        // this map is what the effective source consults.
        val settled = types.allTypes
            .mapNotNull { ast -> ast.name?.takeIf { '<' in it }?.let { it to ast.id.source.identity } }
            .filter { (_, home) -> home.path.isStdMarkerPath() }
        val homeByTemplate = (voted.entries.filter { '<' in it.key }.map { it.key to it.value } + settled)
            .groupBy({ it.first.substringBefore('<') }, { it.second })
            .mapValues { (_, homes) -> homes.groupingBy { it }.eachCount().maxByOrNull { it.value }!!.key }
        val bySibling = voted + types.definitionsByTag.keys
            .filter { '<' in it && it !in voted }
            .mapNotNull { name -> homeByTemplate[name.substringBefore('<')]?.let { name to it } }
        // Last resort, and it is structural rather than evidential: a base class inherits where its
        // derived class went. Bases only — extending it to field types moved nothing on the corpus.
        // `_Vector_alloc_base<unsigned short>` declares three pointers, has no methods, and no
        // instantiation of *that* template anywhere in the corpus has an out-of-line
        // method — so neither the vote nor the sibling pass can reach it. What is known is that
        // `_Vector_base<unsigned short>`, which derives from it, lives in stl_vector.h. Chains run
        // `vector` → `_Vector_base` → `_Vector_alloc_base`, hence the rounds; templates only, so a
        // project class can never be dragged along by a base it shares with the standard library.
        (1..3).fold(bySibling) { homes, _ ->
            homes + types.allTypes
                .flatMap { ast ->
                    val home = ast.name?.let { homes[it] } ?: return@flatMap emptyList()
                    (ast.body as? TypeDecl.Aggregate)?.bases.orEmpty().mapNotNull { base ->
                        (base.type as? TypeDecl.Ref)?.id?.let { types.byId(it) }?.name
                            ?.takeIf { '<' in it && it !in homes }?.let { it to home }
                    }
                }
        }
    }

    /**
     * Every copy of a body several CUs claim at one address — the linker folded them from a
     * definition all of them included. Grouped by mangled name, so the copies can be compared.
     */
    private val comdatCopiesByMangled: Map<String, List<Func>> by lazy {
        harvest.functions.groupBy { it.addr }
            .values.filter { copies -> copies.mapTo(mutableSetOf()) { it.cu }.size > 1 }
            .flatten().groupBy { it.name }
    }

    private val votedHeaderHints: Map<String, GhidraSourceFile> by lazy {
        val funcsByMangled = harvest.functions.filter { (it.sizeBytes ?: 0uL) > 0uL }.associateBy { it.name }
        val defSourcesByName = types.allTypes
            .filter { it.name != null }
            .groupBy({ it.name!! }, { it.id.source.identity })
            .mapValues { it.value.toSet() }
        // Header line-entries sorted by address once, so each method's [lo,hi) range is a binary-searched
        // slice instead of a full scan of every source's entries per method (was O(types × methods ×
        // entries)). Non-header sources never vote, so they're dropped up front.
        val hdrEntries = harvest.sources.entries
            .filter { it.key.filename.hasHeaderExtension() }
            .flatMap { (src, harvested) -> harvested.lineEntries.map { it.addr.offset to src } }
            .sortedBy { it.first }
        val hdrOffsets = LongArray(hdrEntries.size) { hdrEntries[it].first }

        buildMap {
            for ((name, asts) in types.definitionsByTag) {
                val defSources = defSourcesByName[name] ?: continue
                // A template instantiation is the one thing gcc files by accident: it emits
                // `vector<unsigned short>` inside whichever header first needed it, so image.h — a
                // header, hence already past this guard — collected 31 rows of libstdc++. Everything
                // else declared only in headers is left alone, which also bounds what this loop costs.
                val templated = '<' in name
                if (!templated && defSources.all { it.filename.hasHeaderExtension() }) continue
                val methods = asts.flatMap { (it.body as? TypeDecl.Aggregate<*>)?.methods.orEmpty() }
                if (methods.isEmpty()) continue
                // A type's own def sources win by body size, so exclude them from the vote.
                //
                // A merged body's copies are asked first: each claiming CU attributed it to the file
                // *it* saw the definition in, so where they agree, that file is where the definition
                // lives. Where they disagree there is nothing to read — an implicit ctor/dtor clone
                // has no source text of its own and inherits whatever N_SOL the emitter last named
                // (`bouniaf::~bouniaf` reads `iostream` in one CU and `appimage.h` in another). The
                // split is clean on the corpus: instantiations agree and name their defining header,
                // clones disagree (ComdatProvenanceProbe). Disagreement abstains, leaving the N_SOL
                // bursts inside the bodies — the only evidence an out-of-line class ever produces.
                val merged = methods.mapNotNull { m ->
                    val copies = comdatCopiesByMangled[m.mangled ?: return@mapNotNull null].orEmpty()
                    copies.mapNotNull { c -> c.lineEntries.minByOrNull { it.addr.offset }?.source }
                        .distinct().singleOrNull()
                }
                val bursts = mutableListOf<GhidraSourceFile>()
                for (m in methods) {
                    val func = funcsByMangled[m.mangled ?: continue] ?: continue
                    val hi = func.addr.offset + (func.sizeBytes ?: 0uL).toLong()
                    var i = hdrOffsets.lowerBound(func.addr.offset)
                    while (i < hdrEntries.size && hdrOffsets[i] < hi) bursts += hdrEntries[i++].second
                }
                val votes = merged.ifEmpty { bursts }
                    .filter { it.filename.hasHeaderExtension() && it !in defSources }
                    .groupingBy { it }.eachCount()
                val (stdVote, userVote) = votes.entries.partition { it.key.path.isStdMarkerPath() }
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
        sourceFile?.takeIf { body !is TypeDecl.Aggregate && body !is TypeDecl.Enum } ?: id.source.identity

    /** [type]'s hint — the header its methods were compiled into — folded, or null if it has none. */
    fun hintedFor(type: Type) = type.hinted()?.let(sources::fold)

    /** What gcc recorded for [type], folded: its own `N_SOL` where it has one, else its CU. */
    fun recordedFor(type: Type) = sources.fold(type.recorded())

    /** Attribution before a source root has a say — what `baseTypesBySource` groups by. */
    fun baseSourceOf(type: Type) = hintedFor(type) ?: recordedFor(type)
}
