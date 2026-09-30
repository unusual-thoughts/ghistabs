package ghistabs.materialize

import ghidra.app.util.demangler.Demangled
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.Union
import ghidra.util.task.TaskMonitor
import ghistabs.Demangler
import ghistabs.demanglerPath
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Type
import ghistabs.index.*
import ghistabs.materialize.cpp.abi.Rtti
import ghistabs.parse.CATEGORY
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghidra.program.model.data.Enum as GhidraEnum

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
    internal val hints: SourceHints,
    internal val monitor: TaskMonitor = TaskMonitor.DUMMY,
) : DiagnosticSink by sink {
    internal val harvest = hints.harvest
    internal val types = hints.types

    /**
     * Canonical (category, ghidraName) → group; drives TypeRegistry slot assignment. XRef-targets are
     * bucketed into `(category, ghidraName)` slots ([ScopeLocator.classifyGroup] picks each winner), then slots are
     * unified by **content hash** (§20): gcc spells one header two ways, so one logical type lands in
     * several slots (named, anonymous copy, typedef aliases) → several DataTypes → the decompiler picks
     * the wrong same-named one. Within a content class holding exactly one named ghidraName, every slot —
     * anonymous ones included — collapses onto that name's largest slot. Content, not path, is the signal,
     * so it reaches headers that don't fold by basename; distinct-named or unnamed classes stay separate.
     *
     * Slots are for tag definitions only ([TypeGraph.definitionsByTag]). Everything else materializes
     * without one — [materializeTopLevel] for function types and the like, [materializeTypedefs] for
     * the names that bind to a type defined elsewhere.
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
     * [materializeAll] returns its size, and pass C keeps registering after that — ClassApplier's
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

    /** Ids of the types in the DTM before this import: an earlier import's, and analysis's own. */
    private val preexisting = dtm.allDataTypes.asSequence().mapTo(HashSet()) { dtm.getID(it) }

    /**
     * [conflictHandler], except against a type of the same kind that predates this import. That is an
     * earlier import's: a re-import (`Tools > Stabs > Re-import`, or a saved program run again) builds
     * the same types again, and [conflictHandler] would fork a `.conflict` beside each, which every use
     * then points at. A struct, union or enum is reset in place to what this import builds. A function
     * definition is kept as it stands: a swept vftable slot is typed off its target's signature, which
     * that import has since typed, so what this one builds is not what it was.
     *
     * Only the type being resolved gets this: its dependencies go through [conflictHandler].
     */
    private val overHandler = object : DataTypeConflictHandler() {
        override fun resolveConflict(added: DataType, existing: DataType): ConflictResult = when {
            dtm.getID(existing) !in preexisting -> conflictHandler.resolveConflict(added, existing)
            added is FunctionDefinition && existing is FunctionDefinition -> ConflictResult.USE_EXISTING
            existing.isSameKindAs(added) -> ConflictResult.REPLACE_EXISTING
            else -> conflictHandler.resolveConflict(added, existing)
        }

        override fun shouldUpdate(source: DataType, local: DataType) = false

        override fun getSubsequentHandler() = conflictHandler
    }

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
        val placeholder = makePlaceholder(type, location.category, "fwd-decl", location.name).resolveOver()
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
    private fun DataType.resolveIntoDtm(handler: DataTypeConflictHandler = conflictHandler): DataType =
        dtm.resolve(this, handler)

    /** [resolveIntoDtm] over an earlier import's type of the same kind: see [overHandler]. */
    private fun DataType.resolveOver(): DataType = resolveIntoDtm(overHandler)

    /** [register] for a vftable slot's function definition, over an earlier import's: see [overHandler]. */
    internal fun registerOver(dt: DataType): DataType = register(dt, handler = overHandler)

    private fun DataType.isSameKindAs(other: DataType) = when (other) {
        is Structure -> this is Structure
        is Union -> this is Union
        is GhidraEnum -> this is GhidraEnum
        else -> false
    }

    /**
     * [resolveIntoDtm] + remember. Returns the DTM-resolved instance (may differ). With an [id],
     * caches it under [id] for [dataTypeFor]; id-less, buckets it by name in extrasByName.
     */
    internal fun register(dt: DataType, id: GlobalTypeId? = null, handler: DataTypeConflictHandler = conflictHandler) =
        dt.resolveIntoDtm(handler).also { resolved ->
            when (id) {
                null -> extrasByName.getOrPut(resolved.name) { LinkedHashSet() }.add(resolved)
                else -> cache(id, resolved)
            }
        }

    /**
     * Get-or-create a DTM-resident DataType of type [T] at `(category, name)`. One found there is
     * returned as it stands, and one an earlier import left is registered as this one's, with the slot
     * definitions it points at, so a re-import's registry reads as the first's did.
     */
    internal inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T =
        when (val dt = dtm.getDataType(category, name)) {
            is T -> dt.also { if (!isRegistered(it)) adopt(it) }
            else -> register(build()) as T
        }

    internal fun isRegistered(dt: DataType) = extrasByName[dt.name]?.contains(dt) == true

    /**
     * [existing] registered as this import's, as it stands, with the function definitions its slots
     * point at. Kept rather than rebuilt: a swept vftable slot is typed off its target's signature,
     * which the earlier import has since typed, so rebuilding it would not give back what it was.
     */
    internal fun <T : DataType> adopt(existing: T): T = existing.also {
        extrasByName.getOrPut(it.name) { LinkedHashSet() }.add(it)
        for (c in (it as? Structure)?.definedComponents.orEmpty()) {
            val fd = (c.dataType as? Pointer)?.dataType as? FunctionDefinition ?: continue
            if (fd.categoryPath == it.categoryPath) adopt(fd)
        }
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
                ?: if (ast.body is TypeDecl.Aggregate) {
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
    internal fun Type.substitute(): DataType? = resolveBuiltin(body)
        ?: rttiStructs.typeInfoLayout(ghidraName)?.also {
            debug("rtti-pseudo-substituted", "name=$ghidraName")
        }

    internal fun resolveBuiltin(decl: GlobalTypeDecl): DataType? = decl.atBaseWidth().resolveBuiltin()

    /**
     * A `0;-1` range restated as the `@s<n>` the emitter didn't write, its width taken from the base
     * type — read off the harvested ast, never materialized: the base of gcc's `long long unsigned
     * int` is the range itself, which would recurse, and whose own `0;-1` bounds say nothing anyway.
     * That self-reference *is* gcc's way of saying 64-bit, so leaving such a range alone keeps the
     * 64-bit reading. Anything else already carries its own width and is returned untouched.
     */
    private fun GlobalTypeDecl.atBaseWidth(): GlobalTypeDecl = (this as? TypeDecl.Range)?.takeIf { it.sizeBits == null }
        ?.let { range ->
            types.resolveWith(range.inner) { it.takeUnless { d -> d is TypeDecl.Ref || d is TypeDecl.InlineDef } }
                ?.sizeBits
                ?.let { range.copy(sizeAttr = it) }
        } ?: this

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
                Demangler.of(fn.name)?.namespace?.let { putIfAbsent(it.demanglerPath.path, dt) }
            }
            // A member function is not the only symbol that ties a class to its demangled path: a
            // static data member's linkage name carries the same chain, and is the *only* one a
            // pure-constants class has. `std::ctype_base` and `std::__ios_flags` declare no member
            // functions at all, so the loop above can never reach them and their stub had no
            // candidate. Here the owning AST supplies the type directly — no `this` param needed.
            for (ast in types.allTypes) {
                val body = ast.body as? TypeDecl.Aggregate<GlobalTypeId> ?: continue
                val dt = dataTypeFor(ast.id) ?: continue
                for (field in body.fields) {
                    val mangled = field.mangled?.takeIf { field.isStatic } ?: continue
                    Demangler.of(mangled)?.namespace?.let { putIfAbsent(it.demanglerPath.path, dt) }
                }
            }
        }
    }
}
