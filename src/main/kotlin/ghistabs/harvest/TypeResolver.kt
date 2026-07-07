package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.*

/**
 * Indexes the [Harvest]'s typeAsts: id/xref oracle for [contentHash], xref resolution with
 * per-reason failure counters, canonical-key grouping for TypeRegistry slot assignment,
 * and content-distinct collision filtering.
 */
class TypeResolver(val harvest: Harvest, sink: DiagnosticSink = DummySink) :
    DiagnosticSink by sink,
    TypeAstOracle {
    val typeAsts get() = harvest.typeAsts

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

        val tag = baseTag(xref.tagName)
        val sameTagAnyKind = if (tag.isNotEmpty()) astsByBaseTag[tag].orEmpty() else emptyList()
        val sameKind = sameTagAnyKind.filter { it.body.matchesXRefKind(xref.kind) }
        val distinctSizes = sameKind.map { it.body.sizeBytes }.toSet()

        if (sameKind.isNotEmpty() && distinctSizes.size == 1) {
            val resolved = sameKind.first()
            debug("xref-base-tag-resolved", "'${xref.tagName}' → '${resolved.nameOrUnique}'")
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
        log(counter)
        debug("unresolved-xref", "${xref.tagName} [${xref.kind}] ${xrefDiagnosis(xref)}")
        return null
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

    /** Content hash of [body] under this resolver's oracle, sharing the canonicalization cache. */
    fun contentHash(body: TypeDecl<GlobalTypeId>): Int = body.contentHash(this, hashCache)

    /** Multi-body collisions after content-equivalence filtering — only genuinely divergent ones. */
    val divergentCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> by lazy {
        harvest.rawCollisions.filterValues { byName ->
            byName.values.flatten().map { contentHash(it) }.toSet().size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                types.groupBy { contentHash(it) }.map { it.value.first() }.toSet()
            }
        }
    }

    // Index TypeAsts by simple name → BINCL-anchored source of the
    // type's defining declaration. Prefer concrete Struct / Enum
    // bodies over forward-decl `XRef`s and over Refs / aliases:
    // gcc emits XRef stubs for class names mentioned via pointer
    // /reference inside unrelated headers (e.g. `class
    // CSymLexStream;` reachable from `<iostream>` via the include
    // graph), and those XRef stubs share the class's simple name
    // — picking one of them would route the class's methods to
    // `<iostream>` instead of `lexstream.h`.
    val classSourceByName by lazy {
        mutableMapOf<String, String>().apply {
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
                    this[n] = ast.id.source.filename
                }
            }
        }
    }

    private val functionSourceRaw by lazy {
        mutableMapOf<OpenFunction, String>().apply {
            for (f in harvest.openFunctions) {
                if (f.isSyntheticInit) {
                    this[f] = f.cu.filename
                    continue
                }
                // Trust SLINE attribution: the source of the function's lowest-address N_SLINE
                // is where gcc says the body lives. The function carries its own line entries
                // (stab-stream membership), so no address-range scan is needed. Fall back to the
                // class-declaration source only when the function has no line entries
                // (defaulted/implicit methods gcc materialises inside an unrelated template
                // header, e.g. EquExpression's implicit copy ctor emitted inside std::pair).
                f.lineEntries.minByOrNull { it.addr.address.offset }?.let { prologue ->
                    this[f] = prologue.source
                    continue
                }
                f.outermostClass()?.let { classSourceByName[it] }?.let { this[f] = it }
            }
        }
    }

    /** Function → its **canonical** source file (§15), so render compares canonical to canonical. */
    val functionSource: Map<OpenFunction, String> by lazy {
        functionSourceRaw.mapValues { canonicalSource(it.value) }
    }

    /** Raw header-owner hints (§15-independent), computed pre-canonicalization; see [multiSourceHeaderHints]. */
    val multiSourceHeaderHints: Map<String, String> get() = harvest.multiSourceHeaderHints

    // A multi-CU class lands at the header its member SLINEs mostly point to, not the .cpp gcc
    // emitted the body burst in. Typedefs instead trust their N_SOL-effective declSourceFile: a
    // template-instantiation typedef materialised inside a CU (`typedef __true_type __Normal`
    // splayed into main.cpp) still names its real header there, so it renders in the header
    // instead of masquerading as CU-local. Structs/enums keep the hint/CU path — a struct's `:T`
    // body is legitimately CU-emitted (§6), and enum relocation is a broader change left for later.
    private fun TypeAst.effectiveSourceRaw() = name?.let { multiSourceHeaderHints[it] }
        ?: declSourceFile?.takeIf { it.isNotEmpty() && body !is TypeDecl.Struct && body !is TypeDecl.Enum }
        ?: id.source.filename

    /** Type → its **canonical** rendering source (§15), computed once — render's sole type-attribution accessor. */
    val effectiveSourceByType: Map<TypeAst, String> by lazy {
        typeAsts.values.associateWith { canonicalSource(it.effectiveSourceRaw()) }
    }

    /** Type → its **canonical** rendering source (§15). */
    fun effectiveSourceFor(type: TypeAst) = effectiveSourceByType[type] ?: canonicalSource(type.effectiveSourceRaw())

    /**
     * Canonical spelling of [raw] (identity when it doesn't fold). The fold (§15) is computed and
     * applied at the data layer ([Harvester.canonicalizeRenderSources]); `harvest.lineEntries` /
     * `symbolsByCu` keys and their per-record `source`/`sourceFile` are already canonical, so this
     * is only needed for the still-raw `id.source` / `declSourceFile` in type attribution.
     */
    fun canonicalSource(raw: String): String = harvest.sourceCanonicalization[raw] ?: raw

    /**
     * Canonical (CategoryPath, ghidraName) → group. Drives TypeRegistry slot assignment.
     *
     * One grouping pass with §20 content-unification folded in. First every XRef-target type is
     * bucketed into its `(category, ghidraName)` slot and each slot's winner is picked
     * ([classifyGroup]). Then slots are unified by **content hash**: gcc spells one physical header
     * two ways (§15), so one logical type appears several times — a named struct/enum in one
     * spelling, an anonymous copy in another, plus `typedef …;` aliases — landing in distinct slots
     * that would give the DTM several DataTypes for one type (and the decompiler's display-name
     * resolution, scanning all same-named DataTypes, would pick the wrong one). Within each
     * content-equivalence class that has exactly one distinct *named* ghidraName, every slot —
     * including anonymous ones, which carry no name for `keyForAst` to match — collapses onto that
     * name's largest/most-resolved slot. Content identity (not source path) is the signal, so it
     * needs no path canonicalization and reaches headers that don't fold by basename. Classes with
     * two distinct real names (coincidentally identical layout) or no named member are left as
     * separate slots.
     */
    val byCanonicalKey: Map<GhidraKey, CanonicalGroup> by lazy {
        val byGhidraName = typeAsts.values.groupBy { it.ghidraName }
        val attribution = Attribution(
            commonProjectPrefix = commonProjectPrefix(typeAsts.values.map { it.id.source }),
            multiSourceHeaderHints = multiSourceHeaderHints,
        )
        val slots = typeAsts.values
            .filter { it.body.isXRefTarget }
            .groupBy { ast ->
                attribution.keyForAst(ast, byGhidraName.getValue(ast.ghidraName).map { it.id.source }.toSet())
            }
            .map { (key, members) -> classifyGroup(key, members) }

        buildMap {
            for ((_, equivalent) in slots.groupBy { contentHash(it.ast.body) }) {
                val named = equivalent.filter { !it.ast.name.isNullOrEmpty() }
                if (equivalent.size == 1 || named.map { it.ast.ghidraName }.toSet().size != 1) {
                    for (g in equivalent) put(g.key, g)
                    continue
                }
                val winner = named.maxWith(
                    compareBy<CanonicalGroup>({ it.ast.body.sizeBytes })
                        .thenByDescending { countUnresolvedRefs(it.ast.body) }
                        .thenBy { it.key.toString() },
                )
                debug(
                    "canonical-content-merged",
                    "${winner.key}: ${equivalent.size} groups (${equivalent.count {
                        it.ast.name.isNullOrEmpty()
                    }} anon) " +
                        "across ${equivalent.map { it.key.category }.toSet()}",
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
        val byHash = members.groupBy { contentHash(it.body) }
        when {
            byHash.size > 1 -> debug(
                "canonical-key-multi-hash",
                "$key: ${byHash.size} distinct bodies across " +
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
        val Empty = TypeResolver(Harvest(emptyMap()))
    }
}

/**
 * Infer a class's owning header when gcc emitted its `:Tt` definition inside a .cpp rather than a
 * BINCL'd header — the header association is lost at emission, so the def's `id.source` is a
 * misleading .cpp (e.g. AppImage's full def lands only in main.cpp). Majority vote over the N_SOL
 * source of line entries inside the type's member-function bodies: gcc emits `N_SOL("foo.h")` bursts
 * wherever a method inlines header code, so those entries point back at the declaring header
 * (AppImage's destructors inlined into main.cpp carry appimage.h entries).
 *
 * Only types with a .cpp definition source are considered: a def already in a header renders
 * correctly via `id.source`, and a hint could only drag it to a worse one. A real (non-stdlib)
 * header vote always wins. When a type inlines only stdlib code (std::string/std::vector) it has no
 * real-header home; fall back to the stdlib majority *only if the def is scattered across several
 * sources*, to collapse it into one file instead of duplicating it per CU — a single .cpp-local
 * instantiation is left in place rather than dragged into a stdlib header.
 *
 * Computed over **raw** [lineEntries] before §15 path-canonicalization, so the hint (which feeds
 * `Attribution.keyFor`) keeps DTM attribution independent of render-source folding.
 */
fun multiSourceHeaderHints(
    typeAsts: Map<GlobalTypeId, TypeAst>,
    openFunctions: List<OpenFunction>,
    lineEntries: Map<String, List<LineEntry>>,
): Map<String, String> {
    if (openFunctions.isEmpty() || lineEntries.isEmpty()) return emptyMap()
    val astsByName = typeAsts.values.filter { !it.name.isNullOrEmpty() && it.body.isXRefTarget }.groupBy { it.name!! }
    val funcsByMangled = openFunctions.filter { (it.sizeBytes ?: 0uL) > 0uL }.associateBy { it.name }
    val defSourcesByName = typeAsts.values
        .filter { it.name != null }
        .groupBy({ it.name!! }, { it.id.source.filename })
        .mapValues { it.value.toSet() }
    return buildMap {
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
                for ((src, entries) in lineEntries) {
                    if (src in defSources || !src.hasHeaderExtension()) continue
                    val vote = if (src.isStdMarkerPath()) stdVote else userVote
                    for (e in entries) {
                        val a = e.addr.address.offset
                        if (a in lo until hi) vote.merge(src, 1, Int::plus)
                    }
                }
            }
            val winner = userVote.maxByOrNull { it.value }?.key
                ?: stdVote.takeIf { defSources.size > 1 }?.maxByOrNull { it.value }?.key
            winner?.let { put(name, it) }
        }
    }
}
