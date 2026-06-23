package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.GapRecord
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeAst
import ghistabs.harvest.TypeResolver
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.LocalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.isXRefTarget
import ghistabs.runTransaction

class TypeRegistry(
    private val dtm: DataTypeManager,
    private val sink: DiagnosticSink,
    private val diagnostics: StabsDiagnostics,
    private val harvest: Harvest,
    private val resolver: TypeResolver,
) : DiagnosticSink by sink {
    private val byId = mutableMapOf<GlobalTypeId, DataType>()
    private val placeholders = mutableMapOf<GlobalTypeId, DataType>()

    /**
     * DataTypes that originated as an unresolved XRef placeholder. An XRef stub
     * is benign when wrapped in a `Pointer→<stub>` or `Reference→<stub>` — gcc
     * deliberately emits the forward decl in that case and `void*` semantics
     * survive in the listing. It's a real layout loss when one appears as a
     * struct field, base class, or array element — those use sites are caught
     * by [recordXRefStubAt] and emitted as their own degradation bucket.
     */
    private val xrefStubs = mutableSetOf<DataType>()

    /**
     * DataTypes this importer registered in the DTM that don't correspond to
     * a single stab TypeId — `<Class>_vftable` / `<Class>_vtable` structs and
     * per-slot FunctionDefinitions built by [ClassBuilder]. Tracked alongside
     * [byId] so [allCreatedDataTypes] is exhaustive without any DTM-path
     * filtering tricks.
     */
    private val extras = LinkedHashSet<DataType>()

    /**
     * Register [dt] with the DTM (via [DataTypeManager.resolve]) and remember
     * it as something this importer authored. Returns the DTM-resolved
     * instance, which may be a different object if the DTM dedup'd against
     * an existing equivalent. All non-id'd DTM writes (vftable/vtable
     * composites, per-slot FunctionDefinitions, …) should go through this.
     */
    fun register(dt: DataType): DataType {
        val resolved = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
        extras.add(resolved)
        return resolved
    }

    /**
     * Same as [register] but the type is the canonical DataType for [id] —
     * cached in [byId] so subsequent `dataTypeFor(id)` returns it without
     * re-resolving.
     */
    fun register(dt: DataType, id: GlobalTypeId): DataType {
        val resolved = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
        byId[id] = resolved
        return resolved
    }

    /**
     * Get-or-create a DTM-resident DataType at `(category, name)`. If an
     * existing entry there is an instance of [T] it's returned as-is;
     * otherwise [build] is invoked and the result is [register]ed. Used by
     * [ClassBuilder] to manage class-scoped composites without reaching for
     * the DTM directly.
     */
    inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T {
        (dtmLookup(category, name) as? T)?.let { return it }
        return register(build()) as T
    }

    /** Bridge so the inline [getOrRegister] doesn't need the DTM as an inline-visible field. */
    @PublishedApi
    internal fun dtmLookup(category: CategoryPath, name: String): DataType? = dtm.getDataType(category, name)

    /**
     * Every DataType this importer materialised or registered. Exhaustive by
     * construction — every DTM write goes through [register] or sets [byId].
     */
    fun allCreatedDataTypes(): Set<DataType> {
        val result = LinkedHashSet<DataType>(byId.values.size + extras.size)
        result.addAll(byId.values)
        result.addAll(extras)
        return result
    }

    private fun recordXRefStubAt(useSite: String, at: String, dt: DataType) {
        if (dt in xrefStubs) {
            diagnostics.recordDegradation("xref-stub-in-$useSite", at, "type=${dt.name}")
        }
    }

    fun tryGetExisting(gId: GlobalTypeId) = byId[gId] ?: placeholders[gId] ?: harvest.getType(gId)?.let { raw ->
        // Primitives (Range, Builtin, Float, …) resolve directly via BuiltinTable.
        BuiltinTable.resolve(raw.body)?.also { byId[gId] = it }
            // Aggregate bodies (Struct/Union) get an empty-shell placeholder so
            // self-recursive Refs in fields can cycle-break. The placeholder is
            // mutated in-place by materialiseBody later when this id is hit by
            // the materialiseAll winner loop.
            ?: if (raw.body is TypeDecl.Struct) {
                makePlaceholder(raw, CategoryPath("/stabs")).also { placeholders[gId] = it }
            } else {
                // Everything else (Pointer, Array, Reference, Const/Volatile,
                // FunctionT, Method, Enum, InlineDef, Ref, XRef, …) has a
                // perfectly materialisable body — resolve it now. Without this
                // the field-fill path that called us would store the empty
                // placeholder as the field's type (e.g. `_Alloc_hider._M_p`
                // ends up `/stabs/[stdio.h,2]` instead of `char *`).
                resolve(raw)
            }
    }

    /**
     * The materialised DataType for a TypeAst id, as registered by [materialiseAll].
     * Returns null if the id was never registered (e.g. non-registerable typeAst that
     * went through the on-demand `resolve()` path). Prefer this over `dtm.getDataType`
     * — it skips the DTM round-trip and is the authoritative source for the
     * `(category, name)` slot's current DataType.
     */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]

    /**
     * Walk the placeholders map at end-of-import and log every Struct/Union
     * typeAst whose body never made it into the DTM as a non-empty aggregate.
     * These are the source of downstream cascades like `merge-failed`
     * "Offset 0 beyond end of structure" and bogus 1-byte fields in the
     * listing. Naming them at the source makes the cause findable.
     *
     * Only Struct/Union typeAsts are considered: [makePlaceholder] hands out a
     * throwaway empty Structure stub for non-aggregate bodies (Range, Enum,
     * FunctionT, …), but those stubs are never registered in the DTM —
     * `materialiseBody` returns the real DataType directly. Reporting those
     * would be noise, not a bug.
     */
    fun reportSurvivingPlaceholders() {
        for ((id, placeholder) in placeholders) {
            val ast = harvest.getType(id) ?: continue
            if (ast.body !is TypeDecl.Struct) continue
            val composite = placeholder as? Composite ?: continue
            // Empty C++ structs (e.g. tag/trait types) have sizeBytes=1 and no
            // source fields. Ghidra fills the byte with Undefined1 padding, which
            // would otherwise show up as `placeholder-undefined-fields`. That's
            // the correct representation of an empty struct, not a degradation.
            val sourceHasNoMembers =
                ast.body.fields.none { !it.isStatic } && ast.body.bases.isEmpty()
            val tag = when {
                composite.numComponents == 0 && !sourceHasNoMembers -> "placeholder-unresolved"
                composite.allComponentsUndefined() && !sourceHasNoMembers -> "placeholder-undefined-fields"
                else -> continue
            }
            diagnostics.recordDegradation(
                tag,
                "${composite.categoryPath}/${composite.name}",
                when (tag) {
                    "placeholder-unresolved" -> "never had its body materialised (id=$id)"
                    else -> "materialised but every field fell back to Undefined (id=$id)"
                },
            )
        }
    }

    /**
     * A struct "filled with undefined" is one whose every component's data type is in the
     * `UndefinedNDataType` family — i.e. every field's Ref or XRef failed to resolve and
     * the materialiser used the `Undefined4` fallback. From the user's point of view this
     * is no better than an empty placeholder; flagging it separately distinguishes
     * "body never ran" from "body ran but couldn't bind any field type".
     */
    private fun Composite.allComponentsUndefined(): Boolean {
        if (numComponents == 0) return false
        return components.all { it.dataType.name.startsWith("undefined") }
    }

    fun materialiseAll() {
        // Two-phase walk driven by resolver.byCanonicalKey:
        //  1. For each CanonicalGroup, materialise the winner once into its (cat, name)
        //     slot and alias every member's id to the resulting DataType.
        //  2. Handle non-registerable top-level typeAsts (XRef-aliased helpers,
        //     FunctionT, Method, …) via the legacy resolve() path — they need byId
        //     entries for Ref resolution but never occupy a stable Ghidra slot.
        dtm.runTransaction("ghidra-stabs build types") {
            val memberToWinner: Map<GlobalTypeId, TypeAst> = buildMap {
                for (group in resolver.byCanonicalKey.values) {
                    for (m in group.members) put(m, group.ast)
                }
            }
            val winnerCategory: Map<GlobalTypeId, CategoryPath> = buildMap {
                for (group in resolver.byCanonicalKey.values) put(group.ast.id, group.key.category)
            }

            // Pre-seed placeholders for every member id so Ref(id) cycle-breaks during
            // body materialisation. Struct/Union placeholders go into the DTM up-front
            // so later in-place mutations land on the DTM-resident object.
            for (group in resolver.byCanonicalKey.values) {
                val winner = group.ast
                val raw = makePlaceholder(winner, group.key.category)
                val placeholder = if (winner.body is TypeDecl.Struct) {
                    // Add to DTM up-front so later in-place mutations land on
                    // the DTM-resident object. byId is set below by the winner
                    // materialiser; here we just need the DTM-resolved handle.
                    register(raw)
                } else {
                    raw
                }
                for (m in group.members) placeholders.putIfAbsent(m, placeholder)
            }

            // Materialise winners.
            for ((winnerId, category) in winnerCategory) {
                val winner = harvest.getType(winnerId) ?: continue
                val placeholder = placeholders[winnerId]!!
                val materialised = materialiseBody(winner, category, placeholder)
                if (materialised === placeholder) {
                    // Pre-seeded into DTM above (for Struct) or kept in-memory
                    // (for non-Struct, which materialiseBody handled directly).
                    byId[winnerId] = placeholder
                } else {
                    register(materialised, winnerId)
                }
            }
            // Alias members to their winner's DataType.
            for ((memberId, winner) in memberToWinner) {
                byId[winner.id]?.let { byId.putIfAbsent(memberId, it) }
            }

            // Materialise named primitive typedefs (Range, Builtin, Float, etc.).
            // These don't qualify as XRefTarget so they're absent from byCanonicalKey,
            // but stabs assigns them names ("unsigned int", "char", …) that should
            // appear in the DTM as typedef aliases for the corresponding Ghidra builtins.
            // Group by ghidraName to emit exactly one typedef per logical primitive name.
            harvest.typeAsts.values
                .filter { it.name != null && !it.body.isXRefTarget }
                .groupBy { it.ghidraName }
                .forEach { (ghidraName, asts) ->
                    // Per-ast resolution: each CU's typedef has its own id and
                    // body — e.g. one CU emits `bool:t = _Bool` (1 byte) and
                    // another emits `bool:t = int` (4 bytes). Routing every
                    // ast.id to one shared typedef would silently substitute
                    // the wrong size at field-fill time and produce
                    // `bool.conflict` collisions in the DTM. Resolve each
                    // ast's body individually for byId.
                    for (ast in asts) {
                        val resolved = BuiltinTable.resolve(ast.body) ?: dataTypeFor(ast.body) ?: continue
                        byId.putIfAbsent(ast.id, resolved)
                    }
                    // Register one shared typedef under /stabs (or root for
                    // primitives) so DemanglerReplacer can find it as a
                    // candidate for `/Demangler/<ghidraName>`. Use the first
                    // ast's body for the alias target.
                    val firstBody = asts.first().body
                    val typedefTarget = BuiltinTable.resolve(firstBody) ?: dataTypeFor(firstBody) ?: return@forEach
                    val category = if (BuiltinTable.resolve(firstBody) != null) {
                        CategoryPath.ROOT
                    } else {
                        CategoryPath("/stabs")
                    }
                    register(TypedefDataType(category, ghidraName, typedefTarget, dtm))
                }

            // Non-registerable top-level typeAsts (XRef body, FunctionT, Method, …)
            for (ast in harvest.typeAsts.values) {
                if (ast.id in byId) continue
                resolve(ast)
            }
        }
    }

    /**
     * Resolve a TypeDecl encountered inside another type's body (a field's type, a pointer's
     * pointee, a base class's type expression) to a Ghidra DataType.
     *
     * Per kind:
     * - **Ref / InlineDef**: look the TypeId up via byId → placeholders → harvest.
     *   Cycle-safe (placeholders break self-recursion).
     * - **Builtin / Range / Complex / WithSizeAttr**: delegated to [BuiltinTable].
     * - **Pointer / Reference / Const / Volatile / Array**: recurse on the inner type.
     * - **Struct / Enum / FunctionT / Method / XRef**: returns `null`. These aggregate bodies
     *   only have meaning when keyed by a [LocalTypeId]. The DataType for them is the one
     *   registered under that id during [materialiseAll]; passing the body itself loses
     *   that identity, so there is no defined lookup. Callers in possession of the parent
     *   [TypeAst.id] should use `byId[id]` (e.g. inside materialiseBody); callers outside
     *   the registry should look up the materialised type by category+name in the DTM
     *   (see ClassBuilder.build for the canonical pattern).
     */
    fun dataTypeFor(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        is TypeDecl.Ref -> tryGetExisting(decl.id)

        is TypeDecl.InlineDef -> {
            tryGetExisting(decl.id) ?: dataTypeFor(decl.body)?.apply {
                byId[decl.id] = this
            }
        }

        is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin -> {
            BuiltinTable.resolve(decl)
        }

        is TypeDecl.Pointer -> PointerDataType(
            dataTypeFor(decl.pointee) ?: undef("pointer-pointee", "(anon)", decl.pointee),
            4,
            dtm,
        )

        is TypeDecl.Reference -> PointerDataType(
            dataTypeFor(decl.referent) ?: undef("reference-referent", "(anon)", decl.referent),
            4,
            dtm,
        )

        is TypeDecl.Const -> dataTypeFor(decl.inner)

        is TypeDecl.Volatile -> dataTypeFor(decl.inner)

        is TypeDecl.Array -> {
            // For arrays of unresolved element types (e.g. globals whose
            // element refers to a TypeId not in the registry), fall back to
            // ByteDataType, NOT `Undefined1`. The latter is type-equivalent
            // to Ghidra's auto-analysis-placed "this is undefined" bytes, so
            // a downstream data-reference analyzer that sees scalar refs to
            // our array happily re-coalesces it into the `undefined4` form
            // it would have built without us. `byte` is a concrete primitive
            // and survives the round-trip.
            val elem = dataTypeFor(decl.element) ?: ByteDataType.dataType
            // Length resolution priority:
            //   1. `decl.length` (explicit element count from the stab)
            //   2. derive from `indexType` Range as `max - min + 1`
            //      (gcc stabs frequently omit `length` and only encode the
            //      array bound via the index Range — e.g. `BranchInstructions`
            //      = array of EnumInstToken indexed 0..15 → 16 elements)
            //   3. fall back to 1 so ArrayDataType doesn't throw
            val rangeLen = (decl.indexType as? TypeDecl.Range)
                ?.let { it.max - it.min + 1 }
                ?.takeIf { it > 0 }
            val numElements = (decl.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
            ArrayDataType(elem, numElements, elem.length)
        }

        is TypeDecl.FunctionT -> {
            val fd = FunctionDefinitionDataType(CategoryPath("/stabs/unnamed"), "FUNCTION_${decl.hashCode()}", dtm)
            fd.returnType = dataTypeFor(decl.ret) ?: VoidDataType()
            val params = decl.params.mapIndexed { i, p ->
                ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: undef("functionT-param", "(anon)[$i]", p), null)
            }.toTypedArray()
            fd.setArguments(*params)
            fd
        }

        // XRef → canonical TypeAst by (kind, tagName), then look up the
        // materialised DataType by its id. Unified across struct / union
        // / class / enum (the old code asymmetrically asked dataTypeFor()
        // for the resolved body, which the aggregate branch always
        // returns null for — silently dropping every non-struct XRef).
        is TypeDecl.XRef -> resolver.byXRef(decl)?.let { tryGetExisting(it.id) }

        // Aggregate bodies — never referenced directly; only meaningful via TypeId.
        // See kdoc above.
        is TypeDecl.Struct, is TypeDecl.Enum, is TypeDecl.Method -> {
            log("referenced-aggregate", "asked for ref to $decl")
            null
        }
    }

    /**
     * Unified fallback for every `dataTypeFor(...) ?: Undefined4` site. Returns
     * `Undefined4` and records a degradation so the end-of-run dump enumerates
     * every silent coverage loss. [category] is the bucket (e.g. `field-type`,
     * `body-pointer-pointee`); [at] is the qualified offending location
     * (e.g. `Foo.bar`, `Cls::method[2]`); the decl is captured as detail.
     */
    /**
     * Build a [FunctionDefinitionDataType] from stab-level types: resolves
     * [ret] and [params] through [dataTypeFor] (falling back via [undef] when
     * a param doesn't resolve), optionally prepends a `this` arg, and sets the
     * calling convention. Shared by the FunctionT / Method materialiser cases
     * and by the vftable-slot builder in ClassBuilder. The returned DataType
     * is NOT yet added to the DTM — caller decides.
     *
     * [at] is the qualified location used in degradation context (e.g.
     * `"Foo::bar"` or `"Cls::method"`); param fallbacks use `"$at[i]"`.
     */
    fun buildFunctionDefinition(
        category: CategoryPath,
        name: String,
        ret: TypeDecl<GlobalTypeId>,
        params: List<TypeDecl<GlobalTypeId>>,
        thisType: DataType? = null,
        callingConvention: String? = null,
        at: String = name,
    ): FunctionDefinitionDataType {
        val fd = FunctionDefinitionDataType(category, name, dtm)
        fd.returnType = dataTypeFor(ret) ?: run {
            diagnostics.recordDegradation("function-ret-untyped", at, ret.toString())
            VoidDataType()
        }
        val thisParam = thisType?.let { ParameterDefinitionImpl("this", it, null) }
        val otherParams = params.mapIndexed { i, p ->
            ParameterDefinitionImpl(
                "arg$i",
                dataTypeFor(p) ?: undef("function-param", "$at[$i]", p),
                null,
            )
        }
        fd.setArguments(*(listOfNotNull(thisParam) + otherParams).toTypedArray())
        // Calling conventions that aren't known to this program's CompilerSpec
        // (e.g. __thiscall on x86-64 ELF) cause setCallingConvention to throw
        // when the FD is later attached to the DTM. Validate up-front against
        // the DTM's known list and skip silently when unsupported — the FD
        // stays at the default convention.
        if (callingConvention != null && callingConvention in dtm.knownCallingConventionNames) {
            runCatching { fd.setCallingConvention(callingConvention) }
        }
        return fd
    }

    private fun undef(category: String, at: String, decl: TypeDecl<GlobalTypeId>): DataType {
        diagnostics.recordDegradation(category, at, decl.toString())
        return Undefined4DataType.dataType
    }

    private fun makePlaceholder(ast: TypeAst, category: CategoryPath, reason: String = "fwd-decl"): DataType {
        val dt = when (ast.body) {
            is TypeDecl.Struct if (ast.body.kind == AggrKind.UNION) -> UnionDataType(category, ast.ghidraName, dtm)
            is TypeDecl.Struct -> {
                val sz = usefulStructSize(ast.body)
                recordTruncation(ast, ast.body.sizeBytes.toInt(), sz)
                StructureDataType(category, ast.ghidraName, sz, dtm)
            }
            // Enum-bodied placeholder must be an EnumDataType — otherwise the
            // empty StructureDataType leaks into the DTM via replaceAtOffset's
            // auto-register-on-use, then collides with the real Enum when its
            // winner registers under the same (category, name) slot. Field
            // consumers end up holding the zero-length Structure reference.
            is TypeDecl.Enum -> EnumDataType(category, ast.ghidraName, 4, dtm)
            else -> StructureDataType(category, ast.ghidraName, 0, dtm)
        }
        diagnostics.recordPlaceholder(ast.nameOrId, category.toString(), reason)
        return dt
    }

    /**
     * "Useful" size for a Struct body — the last byte we have a description
     * for. stab `sizeBytes` often overshoots:
     *  - bouniaf: `s328` but own fields end at 192 (the 136 trailing
     *    bytes are gcc's allocation for basic_ifstream's subobject that
     *    was never emitted in this CU's stab, only forward-declared).
     *  - bouniaf: `s416` but own fields end at 276.
     *
     * Trusting `sizeBytes` produces structs that are mostly Undefined1
     * padding and confuse cross-CU consumers (bouniaf's compile-
     * time view of bouniaf is 192 bytes, but canonical bouniaf at
     * `sizeBytes` is 328 — the size mismatch silently overwrites the
     * derived class's own fields). Truncating to the last meaningful
     * byte we can describe eliminates both problems.
     *
     * Falls back to `sizeBytes` when there are no own non-static fields
     * (empty class, possibly with bases that take some unknown space).
     */
    private fun usefulStructSize(body: TypeDecl.Struct<GlobalTypeId>): Int {
        val nonStatic = body.fields.filter { !it.isStatic }
        if (nonStatic.isEmpty()) return body.sizeBytes.toInt()
        val fieldEnd = nonStatic.maxOf { ((it.offsetBits + it.sizeBits + 7) / 8).toInt() }
        // Round up to the program's default alignment for trailing
        // padding. DataOrganizationImpl.getAlignedOffset handles both
        // power-of-two and arbitrary alignments uniformly.
        val aligned = DataOrganizationImpl.getAlignedOffset(
            dtm.dataOrganization.defaultAlignment,
            fieldEnd,
        )
        return aligned.coerceAtMost(body.sizeBytes.toInt())
    }

    /**
     * Record truncation events (called from makePlaceholder for Struct
     * bodies) so the diagnostic dump shows exactly which structs lost
     * trailing bytes and how many.
     */
    private fun recordTruncation(ast: TypeAst, originalBytes: Int, truncatedBytes: Int) {
        if (originalBytes <= truncatedBytes) return
        diagnostics.recordDegradation(
            "struct-truncated",
            ast.ghidraName,
            "stab claims $originalBytes bytes, last described byte $truncatedBytes; trimmed ${originalBytes - truncatedBytes}",
        )
    }

    /**
     * Materialise a non-registerable top-level typeAst (XRef alias, FunctionT, Method).
     * Registerable bodies (Struct/Enum) are handled directly in [materialiseAll] via
     * `resolver.byCanonicalKey`.
     */
    private fun resolve(ast: TypeAst): DataType {
        if (ast.body is TypeDecl.XRef) {
            resolver.byXRef(ast.body)?.let { canonical ->
                val dt = byId[canonical.id] ?: resolve(canonical)
                byId[ast.id] = dt
                return dt
            }
        }
        val placeholder = placeholders.getOrPut(ast.id) {
            makePlaceholder(ast, CategoryPath("/stabs"), "ref-stub")
        }
        val materialised = materialiseBody(ast, CategoryPath("/stabs"), placeholder)
        byId.putIfAbsent(ast.id, materialised)
        return materialised
    }

    private fun materialiseBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType =
        when (val body = ast.body) {
            is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin ->
                BuiltinTable.resolve(body) ?: placeholder

            is TypeDecl.Pointer -> PointerDataType(
                dataTypeFor(body.pointee) ?: undef("body-pointer-pointee", ast.nameOrId, body.pointee),
                4,
                dtm,
            )

            is TypeDecl.Reference -> PointerDataType(
                dataTypeFor(body.referent) ?: undef("body-reference-referent", ast.nameOrId, body.referent),
                4,
                dtm,
            )

            is TypeDecl.Const -> dataTypeFor(body.inner) ?: placeholder

            is TypeDecl.Volatile -> dataTypeFor(body.inner) ?: placeholder

            // Look up the INNER (decl.id) typeAst — gcc emits anonymous nested aggregates
            // (e.g. C `struct { ... }` member types in box2d) as InlineDef wrappers around
            // an aggregate body. `dataTypeFor(body)` dispatches to the InlineDef case which
            // calls `tryGetExisting(body.id)` first; that picks up the harvested typeAst
            // for the inner aggregate instead of falling through to the
            // `referenced-aggregate` branch that returns null. Avoids 535 silent
            // null-resolutions on box2d's nested-struct fields.
            is TypeDecl.InlineDef -> dataTypeFor(body)?.also {
                byId[body.id] = it
            } ?: placeholder

            is TypeDecl.Array -> {
                val elem = dataTypeFor(body.element) ?: run {
                    diagnostics.recordDegradation("array-element", ast.nameOrId, body.element.toString())
                    ByteDataType.dataType
                }
                recordXRefStubAt("array-element", ast.nameOrId, elem)
                val rangeLen = (body.indexType as? TypeDecl.Range)
                    ?.let { it.max - it.min + 1 }
                    ?.takeIf { it > 0 }
                val numElements = (body.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
                ArrayDataType(elem, numElements, elem.length)
            }

            is TypeDecl.Enum -> {
                // Pick the smallest power-of-two byte width that fits every
                // member's value. gcc's stab default is 4 bytes for plain
                // enums, but C++ `bool` is emitted as `eFalse:0,True:1,;` —
                // sizeof(bool)==1 by the C++ ABI, so a 4-byte enum overflows
                // any field declared with an 8-bit slot (every
                // bool-as-struct-field in box2d). Size from the values.
                val values = body.members.map { it.second }
                val maxV = values.maxOrNull() ?: 0
                val minV = values.minOrNull() ?: 0
                val sizeBytes = when {
                    minV >= Byte.MIN_VALUE && maxV <= Byte.MAX_VALUE -> 1
                    minV >= 0 && maxV <= 0xFF -> 1
                    minV >= Short.MIN_VALUE && maxV <= Short.MAX_VALUE -> 2
                    minV >= 0 && maxV <= 0xFFFF -> 2
                    else -> 4
                }
                val e = EnumDataType(category, ast.ghidraName, sizeBytes, dtm)
                for ((mname, mval) in body.members) {
                    e.add(mname, mval)
                }
                e
            }

            is TypeDecl.Struct -> {
                // Reuse the placeholder cast to the right type
                val struct: Composite = if (body.kind == AggrKind.UNION) {
                    placeholder as Union
                } else {
                    placeholder as Structure
                }

                // Phase 5: insert base classes as inlined components.
                if (struct is Structure) {
                    // Compute layout boundary to infer size of unresolved bases (offset of next base
                    // or first non-static field — that's at this base subobject must end).
                    val sortedBaseOffsetsBytes = body.bases.map { (it.offsetBits / 8).toInt() }.toSortedSet()
                    val firstFieldOffsetBytes = body.fields
                        .filter { !it.isStatic }
                        .minOfOrNull { (it.offsetBits / 8).toInt() }
                        ?: body.sizeBytes.toInt()

                    val dataTypeByOffset = mutableMapOf<Int, DataType>()
                    val resolvedBaseInfo = mutableMapOf<Int, ResolvedBase>()
                    for (base in body.bases) {
                        val offsetBytes = (base.offsetBits / 8).toInt()
                        val dt = dataTypeFor(base.type)
                        // Compute the layout gap before deciding what to use.
                        // gcc's inheritance line doesn't transmit the
                        // subobject size — the consuming struct's own fields
                        // start at whatever offset the compiler decided
                        // (e.g. bouniaf's CurrentTok at +192 means
                        // bouniaf's subobject is 192 bytes here, even
                        // though the canonical bouniaf is 328 bytes
                        // because another CU saw a richer definition).
                        val nextOffset =
                            sortedBaseOffsetsBytes.firstOrNull { it > offsetBytes } ?: firstFieldOffsetBytes
                        val gap = nextOffset - offsetBytes

                        // Empty placeholders (XRef stubs for unresolvable
                        // forward decls, ref-stubs from non-registerable
                        // typeAsts) show up with `length = 1` because Ghidra
                        // forces a minimum on size-0 Composites — `isZeroLength`
                        // returns the logical truth. Treat those as unresolved.
                        if (dt != null && !dt.isZeroLength && dt.length > 0 && dt.length <= gap) {
                            dataTypeByOffset[offsetBytes] = dt
                            resolvedBaseInfo[offsetBytes] = ResolvedBase(dt.name, dt.length)
                            continue
                        }

                        // Either unresolved, or resolved-but-larger-than-the-gap
                        // (cross-CU size disagreement). Synthesise a gap-sized
                        // placeholder so the base subobject is visible and own
                        // fields don't have to clear half of an oversized base.
                        if (gap <= 0) {
                            // Empty base optimization: the base subobject takes
                            // 0 bytes and is invisible in layout. Resolved-to-
                            // empty + gap-zero is the normal EBO case (e.g.
                            // `std::allocator<char>` inside `_Alloc_hider`).
                            // No degradation — just skip the base insertion
                            // and let the own fields at offset 0 take that
                            // slot.
                            if (dt == null || !dt.isZeroLength) {
                                diagnostics.recordDegradation(
                                    "base-skipped-zero-size",
                                    "${ast.nameOrId}@+$offsetBytes",
                                    "cannot infer size",
                                )
                            } else {
                                diagnostics.inc("base-empty-ebo")
                            }
                            continue
                        }
                        val synthName = "unknown_$offsetBytes"
                        val synthDt = ArrayDataType(Undefined1DataType.dataType, gap, 1)
                        dataTypeByOffset[offsetBytes] = synthDt
                        resolvedBaseInfo[offsetBytes] = ResolvedBase(synthName, gap)
                        val reason = if (dt == null || dt.isZeroLength || dt.length <= 0) {
                            "Ref unresolved, synthesised $gap-byte placeholder"
                        } else {
                            "${dt.name} (${dt.length}b) larger than gap ($gap b); synthesised $gap-byte placeholder"
                        }
                        diagnostics.recordDegradation(
                            "base-synthesized",
                            "${ast.nameOrId}@+$offsetBytes",
                            reason,
                        )
                    }

                    // Build insertion ops directly from the loop above's
                    // results — dataTypeByOffset / resolvedBaseInfo already
                    // encode the right size (resolved-and-fits-in-gap or
                    // gap-sized placeholder). Skip the synthesised placeholders
                    // entirely: a `_base_unknown_N : Undefined1[N]` field
                    // pretends to be a real base subobject, but it's just our
                    // gap-fill — better to leave those bytes as Ghidra's
                    // default Undefined1 components so they read as honest
                    // "we don't know what's here". The `base-synthesized`
                    // degradation already records the diagnostic.
                    val ops = body.bases
                        .sortedBy { it.offsetBits }
                        .mapNotNull { base ->
                            val off = (base.offsetBits / 8).toInt()
                            val info = resolvedBaseInfo[off] ?: return@mapNotNull null
                            // Synthesised placeholders don't get inserted —
                            // we identify them by name (the synth path uses
                            // `unknown_<off>` for resolvedBaseInfo.simpleName).
                            // The bytes stay as Ghidra's default Undefined1
                            // fill so they read as honest "we don't know
                            // what's here" rather than a fake named field.
                            if (info.simpleName.startsWith("unknown_")) return@mapNotNull null
                            val prefix = if (base.isVirtual) "_vbase_" else "_base_"
                            InsertOp(
                                offsetBytes = off,
                                fieldName = prefix + info.simpleName,
                                comment = buildString {
                                    append(base.access.name.lowercase())
                                    if (base.isVirtual) append(" virtual")
                                    append(" base")
                                },
                                baseSimpleName = info.simpleName,
                            )
                        }
                    for (op in ops) {
                        val baseDt = dataTypeByOffset[op.offsetBytes] ?: continue
                        try {
                            struct.replaceAtOffset(
                                op.offsetBytes,
                                baseDt,
                                baseDt.length,
                                op.fieldName,
                                op.comment,
                            )
                            diagnostics.inc("inheritance-applied")
                        } catch (e: java.lang.IllegalArgumentException) {
                            diagnostics.recordDegradation(
                                "base-layout-failed",
                                "${ast.nameOrId}::${op.baseSimpleName}",
                                e.message,
                            )
                            diagnostics.inc("inheritance-failed")
                        }
                    }
                }

                // Compute polymorphic base for inherited vfptr gating
                val polyBase = ClassBuilderHelpers(resolver).firstPolymorphicBase(body)

                // Pre-compute base-occupied offset set so a parser-emitted vptr that lands
                // inside a base subobject is filtered out — regardless of whether we could
                // prove the base polymorphic. When the base is unresolved (synthesised
                // _base_unknown_*) `firstPolymorphicBase` returns null, but the stab still
                // emitted a _vptr$Class at the base's offset, and gcc only does that when
                // the base owns the vfptr. Trying to apply our vptr there just collides
                // with the synthesised base — see bouniaf → ios_base cascade.
                val baseOffsets = body.bases.map { it.offsetBits }.toSet()

                // Existing field loop (unchanged).
                for (field in body.fields) {
                    if (field.isStatic) continue // Skip static fields

                    // Skip parser-emitted _vptr$<class> field if inherited from polymorphic base
                    val isParserEmittedVptr =
                        field.name.startsWith("_vptr$") || field.name.startsWith("_vptr.") || field.name == "_vptr"
                    if (
                        isParserEmittedVptr &&
                        (
                            (polyBase != null && field.offsetBits == polyBase.offsetBits) ||
                                field.offsetBits in baseOffsets
                            )
                    ) {
                        // Inherited vfptr — the _base_<Base> (resolved or synthesised) at
                        // that offset already carries it. Skip.
                        diagnostics.inc("vptr-skipped-inherited")
                        continue
                    }

                    val resolvedFt = dataTypeFor(field.type)
                    val ft = resolvedFt
                        ?: undef("field-type", "${ast.ghidraName}.${field.name}", field.type)
                    if (resolvedFt != null && resolvedFt.name.startsWith("undefined")) {
                        diagnostics.recordDegradation(
                            "field-resolved-to-undefined",
                            "${ast.ghidraName}.${field.name}",
                            "type=${resolvedFt.name} from ${field.type}",
                        )
                    }
                    if (resolvedFt != null) {
                        recordXRefStubAt("field", "${ast.ghidraName}.${field.name}", resolvedFt)
                    }
                    // Empty placeholders (XRef stubs, ref-stubs for non-
                    // primitive bodies that materialised lazily) get Ghidra's
                    // enforced length=1. Inserting that 1 byte where a 4-byte
                    // pointer or whatever the stab said belongs would leave
                    // field.sizeBits/8 - 1 bytes as auto-Undefined holes. If
                    // the resolved type is logically empty, prefer the stab's
                    // declared field size (in bytes) so the field at least
                    // occupies the right slot.
                    val stabBytes = (field.sizeBits / 8).toInt()
                    val len = when {
                        ft.length <= 0 -> stabBytes.takeIf { it > 0 } ?: 4
                        ft.isZeroLength && stabBytes > 0 -> {
                            // Skip the degradation when `ft` is a pre-seeded
                            // placeholder that materialiseAll will fill in-
                            // place (anonymous nested aggregate, sibling
                            // canonical winner not yet materialised). The
                            // Structure/Union is the same DTM-resident object;
                            // mutating it later widens it to its real size,
                            // and our reserved `stabBytes` slot fits exactly.
                            // Only log when the placeholder is *not* tracked
                            // — that's the real unresolvable XRef stub case.
                            if (ft !in placeholders.values) {
                                diagnostics.recordDegradation(
                                    "field-stub-padded",
                                    "${ast.ghidraName}.${field.name}",
                                    "type=${ft.name} (zero-length); padding to stab-declared $stabBytes bytes",
                                )
                            }
                            stabBytes
                        }
                        else -> ft.length
                    }
                    try {
                        when (struct) {
                            is Structure -> struct.replaceAtOffset(
                                (field.offsetBits / 8).toInt(),
                                ft,
                                len,
                                field.name,
                                null,
                            )

                            is Union -> struct.add(ft, field.name, null)

                            else -> {}
                        }
                    } catch (e: Exception) {
                        diagnostics.recordDegradation(
                            "field-dropped",
                            "${ast.nameOrId}.${field.name}",
                            e.message,
                        )
                    }
                }

                // Detect Undefined1 holes in the materialised struct. The old
                // implementation looked for "gaps between consecutive
                // components", which never fired because Ghidra auto-fills
                // every empty byte with a 1-byte Undefined1 component (so
                // consecutive components are always contiguous). What we
                // actually care about: runs of Undefined1 where the stab told
                // us there should be a field. The new pass walks components
                // and reports runs ≥ 4 bytes of unnamed Undefined1.
                if (struct is Structure) {
                    val componentRecords = struct.components.map { c ->
                        Triple(c.fieldName, Pair(c.offset, c.length), c.dataType.name)
                    }
                    val holes = detectUndefinedRuns(componentRecords, minRunBytes = 4)
                    val qualifiedName = "$category/${ast.ghidraName}"
                    diagnostics.recordStructGaps(qualifiedName, holes)
                    if (holes.isNotEmpty()) {
                        val bytesInHoles = holes.sumOf { (it.lengthBits / 8).toInt() }
                        val totalBytes = struct.length
                        if (totalBytes > 0 && bytesInHoles * 4 >= totalBytes) {
                            // ≥25% of the struct is unexplained Undefined1 —
                            // surface as a degradation; this catches the
                            // bouniaf-style "base class invisible"
                            // pattern automatically.
                            diagnostics.recordDegradation(
                                "struct-mostly-undefined",
                                "$category/${ast.ghidraName}",
                                "$bytesInHoles of $totalBytes bytes are unnamed Undefined1 across ${holes.size} run(s)",
                            )
                        }
                    }
                }

                // Task 2: Plate-comment summary on the derived struct (base class metadata).
                if (body.bases.isNotEmpty() && struct is Structure) {
                    val lines = body.bases.sortedBy { it.offsetBits }.joinToString("\n") { base ->
                        val baseName = (dataTypeFor(base.type)?.name) ?: "<unresolved>"
                        val virt = if (base.isVirtual) " virtual" else ""
                        "inherits ${base.access.name.lowercase()}$virt $baseName @ +${base.offsetBits / 8}"
                    }
                    val existing = struct.description ?: ""
                    struct.description =
                        if (existing.isEmpty()) lines else "$existing\n$lines"
                }

                struct
            }

            is TypeDecl.FunctionT -> buildFunctionDefinition(
                category = category,
                name = ast.ghidraName,
                ret = body.ret,
                params = body.params,
                thisType = null,
                callingConvention = null,
                at = ast.ghidraName,
            )

            is TypeDecl.Method -> buildFunctionDefinition(
                category = category,
                name = ast.ghidraName,
                ret = body.ret,
                params = body.params,
                thisType = dataTypeFor(body.cls) ?: undef("method-this-cls", ast.ghidraName, body.cls),
                callingConvention = "__thiscall",
                at = ast.ghidraName,
            )

            is TypeDecl.XRef -> {
                // Resolve `XRef(kind, tagName)` to the canonical struct of
                // that name + kind so an `InlineDef(id, XRef(STRUCT, "Foo"))`
                // typeAst (often emitted by gcc for ABI-internal typeinfo
                // helpers like `__si_class_type_info_pseudo`) doesn't get
                // materialised as a separate empty `XRef_[...]` Structure
                // applied at typeinfo locations. Aliases this id to the
                // canonical DataType for `Foo` via byId.
                // Resolver records the degradation itself (with the right
                // bucket by reason) when the lookup fails — we just alias or
                // fall back to the placeholder.
                resolver.lookupByXRef(body)
                    ?.let { canonical -> tryGetExisting(canonical.id)?.also { byId[ast.id] = it } }
                    ?: placeholder.also { xrefStubs.add(it) }
            }

            // Truly-missing classifier: harvest already exhausted above.
//                val knownTypeIds = emptySet<LocalTypeId>()

//                val classification = ResolverDecision.classifyRef(
//                    body.id,
//                    ast.id.source.cu,
//                    knownTypeIds,
//                    knownFileNums,
//                )
//                val gId = fileResolver.globalIdForCu(body.id)
//                val gId = body.id
            is TypeDecl.Ref -> tryGetExisting(body.id) ?: run {
                diagnostics.recordDegradation(
                    "dangling-ref",
                    ast.nameOrId,
                    "ref to ${body.id} from ${ast.source}",
                )
                Undefined4DataType.dataType
            }
        }

    /**
     * Find a DataType by simple ghidraName (no path), used by DemanglerReplacer.
     * Walks `resolver.byCanonicalKey` — the authoritative (category, name) view —
     * and returns null on ambiguity (no heuristic guess).
     */
    fun findByName(simpleName: String): DataType? {
        val candidates = resolver.byCanonicalKey.keys.filter { it.name == simpleName }
        return when {
            candidates.isEmpty() -> null

            candidates.size == 1 -> dtm.getDataType(candidates[0].category, candidates[0].name)

            else -> {
                log("demangler-ambiguous", "Multiple matches for '$simpleName': $candidates")
                diagnostics.inc("demangler-ambiguous")
                null
            }
        }
    }
}

/**
 * Pure function to compute gaps in a struct's field layout.
 * Takes component records and total struct size, returns list of gaps.
 *
 * @param componentRecords List of fields with offset and length in bytes
 * @param totalLengthBytes Total size of struct in bytes
 * @return List of gaps; empty if fully packed or no components
 */
/**
 * Walk a struct's components and report runs of unnamed Undefined1 padding
 * of length ≥ [minRunBytes]. Unlike `computeGaps` (which assumes Ghidra
 * leaves byte-offset gaps between components — it doesn't, since auto-fill
 * inserts an `Undefined1` for every empty byte), this works on the actual
 * materialised composite to surface the "this struct has a base subobject
 * we couldn't render" / "this struct has trailing padding nobody described"
 * patterns.
 *
 * Each triple is `(fieldName, (offsetBytes, lengthBytes), typeName)`.
 * Returns a `GapRecord` per run, with `prevField` / `nextField` set to
 * the names of the nearest named field on either side (null at the ends).
 */
fun detectUndefinedRuns(
    componentRecords: List<Triple<String?, Pair<Int, Int>, String>>,
    minRunBytes: Int = 4,
): List<GapRecord> {
    val out = mutableListOf<GapRecord>()
    val sorted = componentRecords.sortedBy { it.second.first }

    var runStartIdx = -1
    var runStart = -1
    var runEnd = -1

    fun flushRun(prevName: String?, nextName: String?) {
        if (runStartIdx < 0) return
        val runBytes = runEnd - runStart
        if (runBytes >= minRunBytes) {
            out.add(
                GapRecord(
                    offsetBits = (runStart * 8).toLong(),
                    lengthBits = (runBytes * 8).toLong(),
                    prevField = prevName,
                    nextField = nextName,
                ),
            )
        }
        runStartIdx = -1
    }

    for ((i, comp) in sorted.withIndex()) {
        val (name, offsetLen, typeName) = comp
        val isUnnamed = name.isNullOrEmpty()
        val isUndef = typeName.startsWith("undefined")
        if (isUnnamed && isUndef) {
            if (runStartIdx < 0) {
                runStartIdx = i
                runStart = offsetLen.first
            }
            runEnd = offsetLen.first + offsetLen.second
        } else {
            val prevName = if (runStartIdx > 0) sorted[runStartIdx - 1].first else null
            flushRun(prevName, name)
        }
    }
    val prevName = if (runStartIdx > 0) sorted[runStartIdx - 1].first else null
    flushRun(prevName, null)
    return out
}

fun computeGaps(componentRecords: List<Pair<String, Pair<Int, Int>>>, totalLengthBytes: Int): List<GapRecord> {
    if (componentRecords.isEmpty()) return emptyList()

    val gaps = mutableListOf<GapRecord>()
    // Sort by offset
    val sorted = componentRecords.sortedBy { it.second.first }

    // Check for gaps between consecutive fields
    for (i in 0 until sorted.size - 1) {
        val (currName, currMetrics) = sorted[i]
        val (nextName, nextMetrics) = sorted[i + 1]
        val currOffset = currMetrics.first
        val currLength = currMetrics.second
        val nextOffset = nextMetrics.first
        val currEnd = currOffset + currLength

        if (currEnd < nextOffset) {
            val gapLength = nextOffset - currEnd
            gaps.add(
                GapRecord(
                    offsetBits = (currEnd * 8).toLong(),
                    lengthBits = (gapLength * 8).toLong(),
                    prevField = currName,
                    nextField = nextName,
                ),
            )
        }
    }

    // Check for trailing gap
    val lastRecord = sorted.last()
    val lastOffset = lastRecord.second.first
    val lastLength = lastRecord.second.second
    val lastEnd = lastOffset + lastLength
    if (lastEnd < totalLengthBytes) {
        val trailingGapLength = totalLengthBytes - lastEnd
        gaps.add(
            GapRecord(
                offsetBits = (lastEnd * 8).toLong(),
                lengthBits = (trailingGapLength * 8).toLong(),
                prevField = lastRecord.first,
                nextField = null,
            ),
        )
    }

    return gaps
}
