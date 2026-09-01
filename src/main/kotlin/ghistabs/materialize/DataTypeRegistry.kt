package ghistabs.materialize

import ghidra.app.util.demangler.Demangled
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.util.task.TaskMonitor
import ghistabs.Demangler
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.*
import ghistabs.importer.DemanglerReplacer.Companion.DEMANGLER_CATEGORY
import ghistabs.index.*
import ghistabs.materialize.itanium.Rtti
import ghistabs.parse.CATEGORY
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * DataType cache and DTM facade: owns the id→DataType map, resolves types into the DTM under a
 * shared conflict handler, and hands back placeholders for cycle-breaking. The TypeDecl/TypeAst
 * interpreters live in `Materialization.kt` ([resolveRef]/[materializeBody]/[materializeAll]),
 * placeholder construction in `Placeholders.kt` ([makePlaceholder]), and degradation reporting in
 * `TypeDiagnostics.kt`.
 */
class DataTypeRegistry(
    internal val dtm: DataTypeManager,
    sink: DiagnosticSink,
    internal val diagnostics: StabsDiagnostics,
    internal val harvest: Harvest,
    internal val types: TypeGraph,
    internal val hints: SourceHints,
    internal val monitor: TaskMonitor = TaskMonitor.DUMMY,
) : DiagnosticSink by sink {
    /**
     * Canonical (category, ghidraName) → group; drives TypeRegistry slot assignment. XRef-targets are
     * bucketed into `(category, ghidraName)` slots ([classifyGroup] picks each winner), then slots are
     * unified by **content hash** (§20): gcc spells one header two ways, so one logical type lands in
     * several slots (named, anonymous copy, typedef aliases) → several DataTypes → the decompiler picks
     * the wrong same-named one. Within a content class holding exactly one named ghidraName, every slot —
     * anonymous ones included — collapses onto that name's largest slot. Content, not path, is the signal,
     * so it reaches headers that don't fold by basename; distinct-named or unnamed classes stay separate.
     *
     * Lives here rather than on the index because every reader is this phase and a [TypeLocation] is
     * a DTM `CategoryPath` — materialize vocabulary. The algorithm stays in `index/`: grouping by
     * content and picking winners is indexing, memoizing the result for one pass is not.
     */
    val byLocation: Map<TypeLocation, LocatedType> by lazy { types.locateTypes(hints) }

    private val byId = mutableMapOf<GlobalTypeId, DataType>()
    internal val placeholders = mutableMapOf<GlobalTypeId, DataType>()

    // Baseline the DTM's `.conflict` census at construction (before any of our passes touch the DTM;
    // harvest doesn't). Ghidra's own analysis may have forked some, so the end-of-import delta
    // ([reportConflictDelta]) attributes only the forks the stabs import introduced.
    internal val conflictsBefore = dtm.conflictPaths()

    /** XRef stubs that fell through to placeholders. Use sites are flagged via [recordXRefStubAt]. */
    internal val xrefStubs = mutableSetOf<DataType>()

    /** Id-less DataType registrations (typedefs, vftable/vtable composites, FunctionDefinitions). */
    private val extrasByName = LinkedHashMap<String, LinkedHashSet<DataType>>()

    /**
     * Every DataType this importer materialized or registered. Recomputed per read, not cached:
     * [materializeAll] returns its size, and pass C keeps registering after that — ClassBuilder's
     * member-method FunctionDefinitions — which a snapshot taken at pass B would miss.
     */
    internal val allCreatedDataTypes get() = buildSet {
        addAll(byId.values)
        for (bucket in extrasByName.values) addAll(bucket)
    }

    /**
     * Compromised DataTypes by reason — see [computeDegraded]. Lazily computed the first time
     * [reasonFor] (or [compromisedTypes]) is hit; by then [materializeAll] has already populated
     * [byId] and [xrefStubs].
     */
    internal val degradedBy: Map<DataType, String> by lazy { computeDegraded() }

    // Replace-empty, not keep: when we file a type under its namespace category (scope attribution), it
    // collides with the empty this-param shadow Ghidra's demangler forged there (`std::X::method` → empty
    // `/std/X`). KEEP_HANDLER would return that empty shadow and discard our filled type, so every
    // reference resolves to undefined; REPLACE_EMPTY_STRUCTS fills the shadow with ours (and still
    // RENAME_AND_ADDs two genuinely-distinct non-empty types, like DEFAULT_HANDLER).
    private val conflictHandler = DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER

    internal val rttiStructs by lazy { Rtti(dtm) }

    // ── The only writers of byId / placeholders / xrefStubs. [cache] sets the authoritative
    // resolution for an id; [cacheIfAbsent] is the alias/member fan-out that must not clobber a
    // winner already in the slot; [seedPlaceholder] builds an empty cycle-break stub that
    // [materializeAll] later fills in place, fanning it out across a group's member ids;
    // [markXRefStub] tags a placeholder that never resolved, for degradation reporting. Each
    // returns its dt so it composes inside a resolution chain. ([register] layers [resolveIntoDtm] +
    // [cache] for freshly-built types — the DTM-registering counterpart to bare [cache].) ──

    internal fun <T : DataType> cache(id: GlobalTypeId, dt: T): T = dt.also { byId[id] = it }

    internal fun cacheIfAbsent(id: GlobalTypeId, build: () -> DataType): DataType = byId.getOrPut(id, build)
    internal fun cacheIfAbsent(id: GlobalTypeId, dt: DataType?): DataType? = dt?.let { byId.getOrPut(id) { it } }

    /**
     * Get-or-create the empty cycle-break stub for [this] under [CATEGORY]; [materializeAll] fills it.
     *
     * Deliberately *not* resolved into the DTM, unlike [LocatedType.seedPlaceholder]: a group winner is
     * about to be filled, but this stub may stay empty forever (an XRef nothing ever defines). Resolving
     * an empty struct whose name already exists filled takes the conflict handler's RENAME_AND_ADD path
     * — measured at +714 `.conflict` types on crypto_mi_test_gcc421_fullstabs. Consumers that hand a
     * DataType to Ghidra must therefore check DTM residency; see `DemanglerReplacer.replace`.
     */
    internal fun Type.seedPlaceholder(reason: String): DataType =
        placeholders.getOrPut(id) { makePlaceholder(this, CATEGORY, reason) }

    /**
     * Canonical-group fan-out where every member id  shares its winner's in-flight stub.
     * Winners are always XRef-targets (Struct/Union/Enum), so the stub always goes into the
     * DTM up front — in-place fill then lands on the DTM-resident object — and is shared across
     * the group's member ids so a Ref resolved before the winner materializes pulls in that one.
     */
    internal fun LocatedType.seedPlaceholder() {
        val placeholder = makePlaceholder(type, location.category, "fwd-decl", location.name).resolveIntoDtm()
        for (m in members) placeholders.putIfAbsent(m, placeholder)
    }

    internal fun LocatedType.materialize() {
        val placeholder = placeholders[type.id]!!
        val materialized = materializeBody(type, location.category, placeholder)
        if (materialized === placeholder) cache(type.id, placeholder) else register(materialized, type.id)
        for (memberId in members) cacheIfAbsent(memberId, materialized)
    }

    internal fun DataType.markXRefStub(): DataType = apply { xrefStubs.add(this) }

    /** Resolve [this] into the DTM under the shared conflict handler; returns the DTM-resident instance
     *  (may differ from [this]). No id/name bookkeeping — for stubs whose id lands in [byId] later. */
    internal fun DataType.resolveIntoDtm(): DataType = dtm.resolve(this, conflictHandler)

    /**
     * [resolveIntoDtm] + remember. Returns the DTM-resolved instance (may differ). With an [id],
     * caches it under [id] for [dataTypeFor]; id-less, buckets it by name in extrasByName.
     */
    internal fun register(dt: DataType, id: GlobalTypeId? = null): DataType {
        val resolved = dt.resolveIntoDtm()
        when (id) {
            null -> extrasByName.getOrPut(resolved.name) { LinkedHashSet() }.add(resolved)
            else -> cache(id, resolved)
        }
        return resolved
    }

    /** Get-or-create a DTM-resident DataType of type [T] at `(category, name)`. */
    internal inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T =
        when (val dt = dtm.getDataType(category, name)) {
            is T -> dt
            else -> register(build()) as T
        }

    /**
     * Id → DataType, resolved lazily. Returns the cached type or its in-flight cycle-break
     * placeholder if present; otherwise resolves the harvested ast:
     *  - an authoritative [substitute] (primitive / RTTI pseudo) is a *final* type, cached in [byId];
     *  - a Struct/Union gets an empty placeholder so self-recursive Refs cycle-break — [materializeAll]
     *    fills it in place;
     *  - anything else (Pointer/Array/Const/…) is materialized now, so a field-fill path stores e.g.
     *    `char *`, not an empty placeholder
     */
    internal fun getOrMaterialize(id: GlobalTypeId): DataType? =
        byId[id] ?: placeholders[id] ?: types.byId(id)?.let { ast ->
            ast.substitute()?.let { cache(id, it) }
                ?: if (ast.body is TypeDecl.Struct) {
                    ast.seedPlaceholder("cycle-break")
                } else {
                    materializeTopLevel(ast)
                }
        }

    /**
     * Authoritative, fully-resolved type for an ast gcc references but never defines: a primitive via
     * [resolveBuiltin], or a `__*_type_info_pseudo` RTTI record via [Rtti]. These are final types,
     * not cycle-break stubs — callers cache them in [byId] and must never file them under [xrefStubs].
     */
    internal fun Type.substitute(): DataType? = body.resolveBuiltin()
        ?: rttiStructs.typeInfoLayout(ghidraName)?.also {
            debug("rtti-pseudo-substituted", "name=$ghidraName")
        }

    /** Materialized DataType for [id], authoritative for `(category, name)`. Prefer over `dtm.getDataType`. */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]

    /**
     * Materialized type indexed by the full `/Demangler/...` category path the demangler would mint for
     * its enclosing class — the bridge for typedef-spelled template instantiations the demangler can't
     * match to our stab spelling (`__normal_iterator<CryptoPP::word32*,…>` vs demangled `<unsigned int*,…>`).
     * Every out-of-line member function ties its mangled name to our stab type via the `this`-param
     * pointee, and the demangler builds the class's stub path from the same [Demangled] namespace chain —
     * so keying by that path (not the leaf name, which collides across nested `iterator`/`Item`/…) matches
     * `StubRecord.pathName` exactly, no spelling reconstruction. Built once, O(member functions).
     */
    val byDemangledClass: Map<String, DataType> by lazy {
        buildMap {
            // Raw harvest functions, not index.functions: the index copy exists only to fold source
            // spellings (§15), which is a render concern and nothing read here — thisParamTypeId walks
            // the param's SymbolDecl, and folding rewrites only Symbol.sourceFile. Forcing that lazy
            // would copy every function and its three lists on an import that never renders.
            for (fn in harvest.functions) {
                val dt = types.thisParamTypeId(fn)?.let { dataTypeFor(it) } ?: continue
                Demangler.of(fn.name)?.namespace?.let { putIfAbsent(it.categoryPath.path, dt) }
            }
            // A member function is not the only symbol that ties a class to its demangled path: a
            // static data member's linkage name carries the same chain, and is the *only* one a
            // pure-constants class has. `std::ctype_base` and `std::__ios_flags` declare no member
            // functions at all, so the loop above can never reach them and their stub had no
            // candidate. Here the owning AST supplies the type directly — no `this` param needed.
            for (ast in types.allTypes) {
                val body = ast.body as? TypeDecl.Struct<GlobalTypeId> ?: continue
                val dt = dataTypeFor(ast.id) ?: continue
                for (field in body.fields) {
                    val mangled = field.mangled?.takeIf { field.isStatic } ?: continue
                    Demangler.of(mangled)?.namespace?.let { putIfAbsent(it.categoryPath.path, dt) }
                }
            }
        }
    }
}

/** Replicates the (protected) `DemangledDataType.getDemanglerCategoryPath` + leaf: `/Demangler/<ns…>/<name>`. */
private val Demangled.categoryPath get(): CategoryPath =
    (namespace?.categoryPath ?: DEMANGLER_CATEGORY).extend(name)
