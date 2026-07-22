package ghistabs.harvest

import ghidra.program.model.data.CategoryPath
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.*

/**
 * Indexes the [Harvest]'s typeAsts: id/xref oracle for [contentHash], xref resolution with
 * per-reason failure counters, canonical-key grouping for TypeRegistry slot assignment,
 * and content-distinct collision filtering.
 */
class TypeResolver(val harvest: Harvest, private val foldSources: Boolean = true, sink: DiagnosticSink = DummySink) :
    ContentHasher(),
    DiagnosticSink by sink {
    private val typeAsts get() = harvest.typeAsts

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
            .groupBy { baseTag(it.name!!) }
    }

    // Pre-warm with empty `visited` so collision classification isn't biased by traversal order.
    // Must stay below astsByName/astsByBaseTag: contentHash resolves xrefs through them, and a `by
    // lazy` delegate field is only assigned when construction reaches its declaration — an init block
    // placed above them reads a still-null delegate (NPE, silently swallowed under CONCURRENT analysis).
    init {
        for (ast in typeAsts.values) hashCache[ast.id] = contentHash(ast.body)
    }

    override fun byId(id: GlobalTypeId): TypeAst? = typeAsts[id]

    /** Convenience: id → struct body (null if not a struct). */
    fun getStruct(id: GlobalTypeId): TypeDecl.Struct<GlobalTypeId>? = typeAsts[id]?.body as? TypeDecl.Struct

    /**
     * Resolve [xref] to its canonical [TypeAst]. Tries exact-name, then base-tag fallback
     * (commits only when all same-kind candidates agree on size). On miss bumps
     * `xref-undefined` / `xref-kind-mismatch` / `xref-ambiguous`. [silent] is for the
     * contentHash oracle path which expects misses.
     */
    override fun byXRef(xref: TypeDecl.XRef<GlobalTypeId>, silent: Boolean): TypeAst? {
        astsByName[xref.tagName]
            ?.firstOrNull { it.body.matchesXRefKind(xref.kind) }
            ?.let { return it }

        val tag = baseTag(xref.tagName)
        val sameTagAnyKind = if (tag.isNotEmpty()) astsByBaseTag[tag].orEmpty() else emptyList()
        val sameKind = sameTagAnyKind.filter { it.body.matchesXRefKind(xref.kind) }
        val distinctSizes = sameKind.map { it.body.sizeBytes }.toSet()

        if (sameKind.isNotEmpty() && distinctSizes.size == 1) {
            val resolved = sameKind.first()
            debug("xref-base-tag-resolved", "'${xref.tagName}' → '${resolved.ghidraName}'")
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
    fun byXRef(ast: TypeAst): TypeAst? = (ast.body as? TypeDecl.XRef)?.let { xref ->
        byXRef(xref, silent = true)
    }

    /** One-line snapshot of harvest contents under [xref]'s exact tag and base tag. */
    private fun xrefDiagnosis(xref: TypeDecl.XRef<GlobalTypeId>): String {
        val tag = baseTag(xref.tagName)
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

    /** Multi-body collisions after content-equivalence filtering — only genuinely divergent ones. */
    val divergentCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> by lazy {
        harvest.rawCollisions.filterValues { byName ->
            groupByContent(byName.values.flatten()) { it }.size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                groupByContent(types) { it }.map { it.first() }.toSet()
            }
        }
    }

    // ── §15 source folds (private mechanism): two gcc spellings of one physical header → one output
    // file. Render never sees these — only the folded per-source views in the facade below. ──
    private val sourceFolds: Map<String, String> by lazy {
        foldSourcePaths(
            harvest.lineEntries.keys + harvest.symbolsByCu.keys +
                typeAsts.values.flatMap { listOfNotNull(it.id.source.filename, it.declSourceFile) },
        )
    }

    // [foldSources] off → bypass, so `sourceFolds` is never computed.
    private fun foldSource(raw: String) = if (foldSources) sourceFolds[raw] ?: raw else raw
    private fun LineEntry.folded() = copy(source = foldSource(source))
    private fun SymbolRecord.folded() = copy(sourceFile = sourceFile?.let(::foldSource))

    // name → its defining source. Prefer concrete Struct/Enum over forward-decl XRef stubs: gcc emits
    // those for classes merely mentioned by pointer in unrelated headers (e.g. reachable via <iostream>),
    // and picking one would route the class's methods to that header instead of its real home.
    private val classSourceByName: Map<String, String> by lazy {
        buildMap {
            val bestRank = mutableMapOf<String, Int>()
            for (ast in typeAsts.values) {
                val n = ast.name ?: continue
                val rank = when (ast.body) {
                    is TypeDecl.Struct, is TypeDecl.Enum -> 2
                    is TypeDecl.XRef -> 0
                    else -> 1
                }
                if (rank > (bestRank[n] ?: -1)) {
                    bestRank[n] = rank
                    put(n, ast.id.source.filename)
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
    private val multiSourceHeaderHints: Map<String, String> by lazy {
        val astsByName = typeAsts.values.filter {
            !it.name.isNullOrEmpty() && it.body.isXRefTarget
        }.groupBy { it.name!! }
        val funcsByMangled = harvest.openFunctions.filter { (it.sizeBytes ?: 0uL) > 0uL }.associateBy { it.name }
        val defSourcesByName = typeAsts.values
            .filter { it.name != null }
            .groupBy({ it.name!! }, { it.id.source.filename })
            .mapValues { it.value.toSet() }
        // Header line-entries sorted by address once, so each method's [lo,hi) range is a binary-searched
        // slice instead of a full scan of every source's entries per method (was O(types × methods ×
        // entries)). Non-header sources never vote, so they're dropped up front.
        val hdrEntries = harvest.lineEntries.entries
            .filter { it.key.hasHeaderExtension() }
            .flatMap { (src, entries) ->
                val std = src.isStdMarkerPath()
                entries.map { Triple(it.addr.address.offset, src, std) }
            }
            .sortedBy { it.first }
        val hdrOffsets = LongArray(hdrEntries.size) { hdrEntries[it].first }

        buildMap {
            for ((name, asts) in astsByName) {
                val defSources = defSourcesByName[name] ?: continue
                if (defSources.all { it.hasHeaderExtension() }) continue
                val methods = asts.flatMap { (it.body as? TypeDecl.Struct<*>)?.methods.orEmpty() }
                if (methods.isEmpty()) continue
                // A type's own def sources win by body size, so exclude them from the vote.
                val userVote = mutableMapOf<String, Int>()
                val stdVote = mutableMapOf<String, Int>()
                for (m in methods) {
                    val func = funcsByMangled[m.mangled ?: continue] ?: continue
                    val lo = func.addr.address.offset
                    val hi = lo + (func.sizeBytes ?: 0uL).toLong()
                    var i = hdrOffsets.lowerBound(lo)
                    while (i < hdrEntries.size && hdrOffsets[i] < hi) {
                        val (_, src, isStd) = hdrEntries[i++]
                        if (src !in defSources) (if (isStd) stdVote else userVote).merge(src, 1, Int::plus)
                    }
                }
                val winner = userVote.maxByOrNull { it.value }?.key
                    ?: stdVote.takeIf { defSources.size > 1 }?.maxByOrNull { it.value }?.key
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
    private fun TypeAst.effectiveSource() = foldSource(
        name?.let { multiSourceHeaderHints[it] }
            ?: declSourceFile?.takeIf { it.isNotEmpty() && body !is TypeDecl.Struct && body !is TypeDecl.Enum }
            ?: id.source.filename,
    )

    private val effectiveSourceByType: Map<TypeAst, String> by lazy {
        typeAsts.values.associateWith { it.effectiveSource() }
    }

    // ── Render facade: per-source views with every source spelling already folded (§15). ──

    /** N_SLINE entries per source, re-sorted: folded spellings each arrive (line, addr)-sorted, but
     *  their concatenation isn't, and render's SLINE annotations need the merged bucket sorted. */
    val linesBySource: Map<String, List<LineEntry>> by lazy {
        harvest.lineEntries.entries
            .groupBy({ foldSource(it.key) }, { it.value })
            .mapValues { (_, lists) ->
                lists.flatten().map { it.folded() }.sortedWith(compareBy({ it.line }, { it.addr.offset }))
            }
    }

    /** File-scope symbols per source. */
    val symbolsBySource: Map<String, List<SymbolRecord>> by lazy {
        harvest.symbolsByCu.entries
            .groupBy({ foldSource(it.key) }, { it.value })
            .mapValues { (_, lists) -> lists.flatten().map { it.folded() } }
    }

    /** Open functions with their line entries / params / locals folded onto output spellings. */
    val functions: List<OpenFunction> by lazy {
        harvest.openFunctions.map { f ->
            f.copy(
                lineEntries = f.lineEntries.map { it.folded() }.toMutableList(),
                params = f.params.map { it.folded() }.toMutableList(),
                locals = f.locals.map { it.folded() }.toMutableList(),
            )
        }
    }

    /** Function → its source: lowest-address SLINE, else the class-decl source (gcc-implicit methods). */
    val functionSource: Map<OpenFunction, String> by lazy {
        functions.mapNotNull { f ->
            when {
                f.isSyntheticInit -> foldSource(f.cu.filename)

                else -> f.lineEntries.minByOrNull { it.addr.address.offset }?.source
                    ?: f.outermostClass()?.let { classSourceByName[it] }?.let(::foldSource)
            }?.let { f to it }
        }.toMap()
    }

    /** Type → its rendering source (§15) — render's sole type-attribution accessor. */
    fun effectiveSourceFor(type: TypeAst) = effectiveSourceByType[type] ?: type.effectiveSource()

    /** Every source file render emits, from line entries, function bodies, and type declarations. */
    val sources: Set<String> by lazy {
        (linesBySource.keys + functionSource.values + typeAsts.values.map { effectiveSourceFor(it) })
            .filter { it.isNotEmpty() }.toSet()
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
    val byCanonicalKey: Map<GhidraKey, CanonicalGroup> by lazy {
        val byGhidraName = typeAsts.values.groupBy { it.ghidraName }
        val attribution = Attribution(
            commonProjectPrefix = commonProjectPrefix(typeAsts.values.map { it.id.source }),
            multiSourceHeaderHints = multiSourceHeaderHints,
        )

        fun headerKey(ast: TypeAst) =
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
        val enclosingByNestedId: Map<GlobalTypeId, TypeAst> = buildMap {
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

        fun scopeKey(ast: TypeAst): GhidraKey? {
            // Method-bearing: file under the demangler's namespace category, named by its own leaf — the
            // exact (category, name) Ghidra's this-param class-struct creator uses (same GnuDemangler), so
            // our filled slot IS the slot it would otherwise forge empty. byCanonicalKey demotes to header
            // only on a genuine content collision within a (scope, leaf). REQUIRES [TypeRegistry.register]
            // to replace Ghidra's empty namespace shadows (REPLACE_EMPTY_STRUCTS) — else `dtm.resolve`
            // keeps the empty shadow at the colliding path and every reference resolves to it (all-undef).
            ast.demangledClassPath()?.let { return GhidraKey(scopeCategory(it.dropLast(1)), it.last()) }

            // Method-less nested member type (`_Alloc_hider`, `_Rep`, `sentry`) — no mangled method to
            // scope it, so it otherwise collides char-vs-wchar under one bare-name header key. Recover the
            // enclosing template from its own `Outer::Inner` stab name, else from the struct that holds it
            // by value, and file it under that template's member category — the slot its qualified,
            // method-bearing sibling already occupies, so the two unify instead of forking a `.conflict`.
            val (enclosingName, leaf) = ast.name?.let(::splitQualified)?.takeIf { it.size > 1 }
                ?.let { it.dropLast(1).joinToString("::") to it.last() }
                ?: enclosingByNestedId[ast.id]?.name?.let { it to ast.ghidraName }
                ?: return null
            return memberCategoryByClass[canonTemplateName(enclosingName)]?.let { GhidraKey(it, leaf) }
        }

        // Scope→header→hash ladder. A type whose enclosing C++ scope is derivable (any member's
        // mangled name yields one) files under that namespace category — matching where Ghidra's
        // this-param class-struct creator looks, so our filled type is the one it reuses instead of
        // synthesising an empty stub. Header attribution is the fallback for method-less types (C
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
                    if (groupByContent(owners) { it.body }.size == 1) {
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
            for (equivalent in groupByContent(slots) { it.ast.body }) {
                val named = equivalent.filter { !it.ast.name.isNullOrEmpty() }
                if (equivalent.size == 1 || named.map { it.ast.ghidraName }.toSet().size != 1) {
                    for (g in equivalent) put(g.key, g)
                    continue
                }
                // Same layout ⇒ same size, so the size tiebreak ties; prefer the method-bearing copy so
                // its methods (§C vtables / __thiscall) and its scope category win over a method-less copy.
                val winner = named.maxWith(
                    compareBy<CanonicalGroup> { it.ast.body.sizeBytes }
                        .thenBy { (it.ast.body as? TypeDecl.Struct)?.methods?.size ?: 0 }
                        .thenByDescending { countUnresolvedRefs(it.ast.body) }
                        .thenBy { it.key.toString() },
                )
                debug(
                    "canonical-content-merged",
                    "${winner.key}: ${equivalent.size} groups (${
                        equivalent.count { it.ast.name.isNullOrEmpty() }
                    } anon) across ${equivalent.map { it.key.category }.toSet()}",
                )
                put(
                    winner.key,
                    CanonicalGroup(
                        winner.key,
                        winner.ast,
                        equivalent.flatMap {
                            it.members
                        },
                        winner.distinct,
                    ),
                )
            }
        }
    }

    private fun classifyGroup(key: GhidraKey, members: List<TypeAst>): CanonicalGroup {
        val distinctKinds = members.map { it.body::class }.toSet()
        if (distinctKinds.size > 1) {
            warn(
                "canonical-key-multi-kind",
                "$key: ${distinctKinds.map { it.simpleName }}",
            )
        }
        val contentClasses = groupByContent(members) { it.body }
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
        // Winner: largest body → fewest unresolved Refs → first by source filename (stable tiebreak).
        // Fewest-unresolved picks the most-resolved variant when CUs disagree on gcc-implicit slots.
        val winner = members.maxWithOrNull(
            compareBy<TypeAst> { it.body.sizeBytes }
                .thenByDescending { countUnresolvedRefs(it.body) }
                .thenBy { it.id.source.filename },
        )!!
        return CanonicalGroup(key, winner, members.map { it.id }, contentClasses.size)
    }

    private fun countUnresolvedRefs(body: TypeDecl<GlobalTypeId>): Int {
        if (body !is TypeDecl.Struct) return 0
        return body.fields.count { f -> walksToUnresolvedRef(f.type) }
    }

    /** Id of the struct/union [t] embeds by value (through Ref/InlineDef/Const/Volatile only, never a
     *  pointer/array), or null — the containment edge that scopes a method-less nested member type. */
    private tailrec fun byValueStructId(t: TypeDecl<GlobalTypeId>): GlobalTypeId? = when (t) {
        is TypeDecl.Ref -> t.id.takeIf { typeAsts[it]?.body is TypeDecl.Struct }
        is TypeDecl.InlineDef -> if (t.body is TypeDecl.Struct) t.id else byValueStructId(t.body)
        is TypeDecl.Const -> byValueStructId(t.inner)
        is TypeDecl.Volatile -> byValueStructId(t.inner)
        else -> null
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
        val Empty = TypeResolver(Harvest(emptyMap()))
    }
}
