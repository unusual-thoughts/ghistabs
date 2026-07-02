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

    /** XRef stubs that fell through to placeholders. Use sites are flagged via [recordXRefStubAt]. */
    private val xrefStubs = mutableSetOf<DataType>()

    /** Id-less DataType registrations (typedefs, vftable/vtable composites, FunctionDefinitions). */
    private val extrasByName = LinkedHashMap<String, LinkedHashSet<DataType>>()

    /**
     * Compromised DataTypes — anonymous (no name in stab), empty-placeholder (body never
     * materialised), or all-Undefined (body ran but bound nothing). Lazily computed from
     * [byId] / [xrefStubs] / [harvest] the first time [reasonFor] (or [compromisedTypes]) is hit;
     * by then [materialiseAll] has already populated [byId] and [xrefStubs].
     */
    private val degradedBy: Map<DataType, String> by lazy {
        val out = mutableMapOf<DataType, String>()
        fun classify(ast: TypeAst, dt: DataType) {
            if (out.containsKey(dt)) return
            // Unresolved XRef placeholders are flagged unconditionally — their dt is an
            // empty Composite we created for the stub, not aliased from elsewhere.
            if (xrefStubs.contains(dt)) {
                out[dt] = "xref-stub"
                return
            }
            // Skip wrapper / alias bodies — their byId points to the wrapped target's dt.
            // An anonymous `InlineDef(id, Pointer(X))` aliases to `X *32` (Ghidra auto-named
            // from its target); an XRef body that resolved via `resolver.byXRef` aliases to
            // the canonical struct's dt. Letting those classify would misattribute named
            // targets as anonymous. Only Struct/Enum/FunctionT/Method bodies actually own
            // their own dt with their own ghidraName.
            when (ast.body) {
                is TypeDecl.Ref, is TypeDecl.InlineDef,
                is TypeDecl.Pointer, is TypeDecl.Reference,
                is TypeDecl.Const, is TypeDecl.Volatile,
                is TypeDecl.Array, is TypeDecl.WithSizeAttr,
                is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.Float, is TypeDecl.Complex,
                is TypeDecl.XRef,
                -> return

                else -> {}
            }
            val reason = when {
                ast.name == null -> "anonymous"
                dt is Composite && dt.numComponents == 0 -> "empty-placeholder"
                dt is Composite && dt.allComponentsUndefined() -> "all-undefined"
                else -> null
            }
            if (reason != null) out[dt] = reason
        }
        // Canonical-group winners: the ast that actually built the dt. Non-winner
        // member ids alias to the same dt — don't let an anonymous member misclassify
        // a named winner's dt.
        for (group in resolver.byCanonicalKey.values) {
            byId[group.ast.id]?.let { classify(group.ast, it) }
        }
        // Non-canonical top-level asts (XRef aliases, FunctionT, Method, …) that
        // materialised through resolve(); their own ast.id owns the dt directly.
        val canonicalIds = resolver.byCanonicalKey.values.flatMap { it.members }.toSet()
        for (ast in harvest.typeAsts.values) {
            if (ast.id in canonicalIds) continue
            byId[ast.id]?.let { classify(ast, it) }
        }
        out
    }

    /** Resolve [dt] into the DTM and remember it. Returns the DTM-resolved instance (may differ). */
    fun register(dt: DataType): DataType {
        val resolved = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
        extrasByName.getOrPut(resolved.name) { LinkedHashSet() }.add(resolved)
        return resolved
    }

    /** Like [register] but caches the result under [id] for [dataTypeFor]. */
    fun register(dt: DataType, id: GlobalTypeId): DataType {
        val resolved = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER)
        byId[id] = resolved
        return resolved
    }

    /** Get-or-create a DTM-resident DataType of type [T] at `(category, name)`. */
    inline fun <reified T : DataType> getOrRegister(category: CategoryPath, name: String, build: () -> T): T {
        (dtmLookup(category, name) as? T)?.let { return it }
        return register(build()) as T
    }

    @PublishedApi
    internal fun dtmLookup(category: CategoryPath, name: String): DataType? = dtm.getDataType(category, name)

    /** Every DataType this importer materialised or registered. */
    fun allCreatedDataTypes(): Set<DataType> {
        val result = LinkedHashSet<DataType>()
        result.addAll(byId.values)
        for (bucket in extrasByName.values) result.addAll(bucket)
        return result
    }

    private fun recordXRefStubAt(useSite: String, at: String, dt: DataType) {
        if (dt in xrefStubs) {
            diagnostics.recordDegradation("xref-stub-in-$useSite", at, "type=${dt.name}")
        }
    }

    fun tryGetExisting(gId: GlobalTypeId) = byId[gId] ?: placeholders[gId] ?: harvest.getType(gId)?.let { raw ->
        BuiltinTable.resolve(raw.body)?.also { byId[gId] = it }
            // Struct/Union: empty placeholder so self-recursive Refs cycle-break;
            // mutated in-place when materialiseAll reaches this id.
            ?: if (raw.body is TypeDecl.Struct) {
                makePlaceholder(raw, CategoryPath("/stabs")).also { placeholders[gId] = it }
            } else {
                // Pointer/Array/Const/etc. — materialisable now. Without this,
                // a calling field-fill path would store an empty placeholder
                // instead of e.g. `char *` (`_Alloc_hider._M_p` regression).
                resolve(raw)
            }
    }

    /** Materialised DataType for [id], authoritative for `(category, name)`. Prefer over `dtm.getDataType`. */
    fun dataTypeFor(id: GlobalTypeId): DataType? = byId[id]

    /**
     * Log every Struct/Union typeAst whose body never made it into the DTM as a non-empty aggregate.
     * These cause downstream `merge-failed` "Offset 0 beyond end of structure" cascades.
     */
    fun reportSurvivingPlaceholders() {
        for ((id, placeholder) in placeholders) {
            val ast = harvest.getType(id) ?: continue
            if (ast.body !is TypeDecl.Struct) continue
            val composite = placeholder as? Composite ?: continue
            // Empty C++ trait/tag types: sizeBytes=1, no source members. Ghidra fills
            // with Undefined1; that's correct, not a degradation.
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

    /** Every component is in the `UndefinedN` family — distinguishes "body ran but bound nothing" from "body never ran". */
    private fun Composite.allComponentsUndefined(): Boolean {
        if (numComponents == 0) return false
        return components.all { it.dataType.name.startsWith("undefined") }
    }

    fun materialiseAll() {
        // Two phases: (1) materialise each CanonicalGroup winner into its (cat,name)
        // slot and alias members to it; (2) non-registerable top-level asts
        // (FunctionT, Method, XRef aliases) via resolve() — byId only, no DTM slot.
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
                val placeholder = if (winner.body is TypeDecl.Struct) register(raw) else raw
                for (m in group.members) placeholders.putIfAbsent(m, placeholder)
            }

            for ((winnerId, category) in winnerCategory) {
                val winner = harvest.getType(winnerId) ?: continue
                val placeholder = placeholders[winnerId]!!
                val materialised = materialiseBody(winner, category, placeholder)
                if (materialised === placeholder) {
                    byId[winnerId] = placeholder
                } else {
                    register(materialised, winnerId)
                }
            }
            for ((memberId, winner) in memberToWinner) {
                byId[winner.id]?.let { byId.putIfAbsent(memberId, it) }
            }

            // Named primitive typedefs ("unsigned int", "char", …) — not XRefTargets so
            // absent from byCanonicalKey, but stabs gives them names worth exposing as
            // typedef aliases. Group by ghidraName for one typedef per logical name.
            harvest.typeAsts.values
                .filter { it.name != null && !it.body.isXRefTarget }
                .groupBy { it.ghidraName }
                .forEach { (ghidraName, asts) ->
                    // Per-ast resolution: one CU emits `bool:t=_Bool` (1B), another
                    // `bool:t=int` (4B). Sharing one typedef across all ids would
                    // produce wrong field sizes and `bool.conflict` in the DTM.
                    for (ast in asts) {
                        val resolved = BuiltinTable.resolve(ast.body) ?: dataTypeFor(ast.body) ?: continue
                        byId.putIfAbsent(ast.id, resolved)
                    }
                    // One shared typedef under /stabs (or root for primitives) for
                    // DemanglerReplacer to substitute into `/Demangler/*` stubs.
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

    /** Reason the DataType is compromised (anonymous / empty / all-Undefined / xref-stub), or null. */
    fun reasonFor(dt: DataType?): String? = dt?.let { degradedBy[it] }

    /** Snapshot of compromised DataTypes by reason — for the registry dump. */
    fun compromisedTypes(): Map<String, List<DataType>> = degradedBy.entries.groupBy({ it.value }, { it.key })

    /** gcc/gdb (stabsread.c): `Ref(self.id)` encodes void — used for void returns and method-args sentinel. */
    private fun isVoidSelfRef(id: GlobalTypeId): Boolean {
        val ast = harvest.getType(id) ?: return false
        val body = ast.body
        return body is TypeDecl.Ref && body.id == id
    }

    /**
     * Resolve a TypeDecl reference site to a DataType. Struct/Enum/Method/XRef return null
     * (they only have identity through their owning TypeAst id; use [tryGetExisting] for those).
     */
    fun dataTypeFor(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        is TypeDecl.Ref -> tryGetExisting(decl.id)
            ?: if (isVoidSelfRef(decl.id)) VoidDataType() else null

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
            dtm.dataOrganization.pointerSize,
            dtm,
        )

        is TypeDecl.Reference -> PointerDataType(
            dataTypeFor(decl.referent) ?: undef("reference-referent", "(anon)", decl.referent),
            dtm.dataOrganization.pointerSize,
            dtm,
        )

        is TypeDecl.Const -> dataTypeFor(decl.inner)

        is TypeDecl.Volatile -> dataTypeFor(decl.inner)

        is TypeDecl.Array -> {
            // ByteDataType (not Undefined1) for unresolved elements: Undefined1 is
            // type-equivalent to Ghidra's auto-analysis "undefined" bytes, so a downstream
            // data-ref analyzer will recoalesce our array into `undefined4`.
            val elem = dataTypeFor(decl.element) ?: ByteDataType.dataType
            // Length: decl.length, else derive from indexType Range as max-min+1
            // (gcc often omits length, encodes bound only via Range — e.g.
            // BranchInstructions indexed 0..15 → 16 elements), else 1.
            val rangeLen = (decl.indexType as? TypeDecl.Range)
                ?.let { it.max - it.min + 1 }
                ?.takeIf { it > 0 }
            val numElements = (decl.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
            ArrayDataType(elem, numElements, elem.length)
        }

        is TypeDecl.FunctionT -> buildFunctionDefinition(
            category = CategoryPath("/stabs/unnamed"),
            name = "FUNCTION_${decl.hashCode()}",
            ret = decl.ret,
            params = decl.params,
            at = "FunctionT(anon)",
        )

        // XRef → canonical TypeAst by (kind, tagName), then materialised DataType
        // by id. Unified across struct/union/class/enum.
        is TypeDecl.XRef -> resolver.byXRef(decl)?.let { tryGetExisting(it.id) }

        // Aggregate bodies — meaningful only via owning TypeId; see kdoc.
        is TypeDecl.Struct, is TypeDecl.Enum, is TypeDecl.Method -> {
            log("referenced-aggregate", "asked for ref to $decl")
            null
        }
    }

    /**
     * Build a FunctionDefinition (not yet added to DTM) from stab types. Resolves
     * [ret]/[params] via [dataTypeFor], handles gcc's void-sentinel arg-list terminator,
     * and applies [callingConvention] if the program's CompilerSpec accepts it.
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
        // gcc method signatures end in a void sentinel; passing it would trip
        // ParameterDefinitionImpl's "void type not permitted" assertion. Drop the
        // trailing void; substitute Undefined4 mid-list to keep arity stable.
        val effectiveParams = if (params.isNotEmpty() && dataTypeFor(params.last()) is VoidDataType) {
            params.dropLast(1)
        } else {
            params
        }
        // gcc `#` method form puts `this` AS THE FIRST PARAM (gdb stabsread.c::read_args:
        // "We should read at least the THIS parameter here."). When [thisType] is set we
        // just name the first param `this`.
        val argDefs = effectiveParams.mapIndexed { i, p ->
            val resolved = dataTypeFor(p) ?: undef("function-param", "$at[$i]", p)
            val safe = if (resolved is VoidDataType) Undefined4DataType.dataType else resolved
            val argName = if (i == 0 && thisType != null) "this" else "arg$i"
            ParameterDefinitionImpl(argName, safe, null)
        }.toMutableList()
        // Broken-emitter guard: gdb's read_args has the same complaint for stabs that
        // omit the THIS param. Without this, a __thiscall FD with arity 0 silently
        // produces a wrong-shaped signature.
        if (thisType != null && argDefs.isEmpty()) {
            val safe = if (thisType is VoidDataType) PointerDataType(VoidDataType(), dtm) else thisType
            argDefs += ParameterDefinitionImpl("this", safe, null)
        }
        fd.setArguments(*argDefs.toTypedArray())
        // Skip unsupported conventions (e.g. __thiscall on x86-64 ELF would throw
        // when the FD attaches to the DTM).
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
            is TypeDecl.Struct if (ast.body.rawKind == AggrKind.UNION) -> UnionDataType(category, ast.ghidraName, dtm)

            is TypeDecl.Struct -> {
                val sz = usefulStructSize(ast.body)
                recordTruncation(ast, ast.body.sizeBytes.toInt(), sz)
                StructureDataType(category, ast.ghidraName, sz, dtm)
            }

            // Enum placeholder MUST be EnumDataType — a Structure stub would leak via
            // replaceAtOffset's auto-register and collide with the real Enum at the same slot.
            is TypeDecl.Enum -> EnumDataType(category, ast.ghidraName, 4, dtm)

            else -> StructureDataType(category, ast.ghidraName, 0, dtm)
        }
        diagnostics.recordPlaceholder(ast.nameOrUnique, category.toString(), reason)
        return dt
    }

    /**
     * Last-described-byte size for a Struct, since stab `sizeBytes` often overshoots
     * (CLexStream s328 but own fields end at 192; CSymLexStream s416 vs 276 — trailing
     * bytes are gcc's allocation for a subobject only forward-declared in this CU).
     * Trusting sizeBytes silently overwrites a derived class's own fields when the
     * canonical-but-oversized winner is selected. Trim only when the gap > maxFieldSize
     * (upper bound on legitimate tail padding without knowing the struct's alignment).
     */
    private fun usefulStructSize(body: TypeDecl.Struct<GlobalTypeId>): Int {
        val nonStatic = body.fields.filter { !it.isStatic }
        if (nonStatic.isEmpty()) return body.sizeBytes.toInt()
        val fieldEnd = nonStatic.maxOf { ((it.offsetBits + it.sizeBits + 7) / 8).toInt() }
        val claimed = body.sizeBytes.toInt()
        val maxFieldSize = nonStatic.maxOf { ((it.sizeBits + 7) / 8).toInt() }
        return if (claimed - fieldEnd > maxFieldSize) fieldEnd else claimed
    }

    private fun recordTruncation(ast: TypeAst, originalBytes: Int, truncatedBytes: Int) {
        if (originalBytes <= truncatedBytes) return
        diagnostics.recordDegradation(
            "struct-truncated",
            ast.ghidraName,
            "stab claims $originalBytes bytes, last described byte $truncatedBytes; trimmed ${originalBytes - truncatedBytes}",
        )
    }

    /** Materialise a non-registerable top-level ast (XRef alias, FunctionT, Method). */
    private fun resolve(ast: TypeAst): DataType {
        if (ast.body is TypeDecl.XRef) {
            resolver.byXRef(ast.body)?.let { canonical ->
                val dt = byId[canonical.id] ?: resolve(canonical)
                byId[ast.id] = dt
                return dt
            }
        }
        // Void self-ref: resolve before any placeholder is created, otherwise
        // tryGetExisting returns the placeholder and the VoidDataType fallback never fires.
        if (ast.body is TypeDecl.Ref && ast.body.id == ast.id) {
            val void = VoidDataType()
            byId[ast.id] = void
            return void
        }
        val placeholder = placeholders.getOrPut(ast.id) {
            makePlaceholder(ast, CategoryPath("/stabs"), "ref-stub")
        }
        val materialised = materialiseBody(ast, CategoryPath("/stabs"), placeholder)
        byId.putIfAbsent(ast.id, materialised)
        return materialised
    }

    /**
     * Size enums per gdb's `stabsread.c::read_enum_type`: `sizeof(int)` unless gcc emits an
     * explicit `@s<bits>` (`-fshort-enums`). bool doesn't reach this path — it comes through
     * BuiltinTable slot -16.
     */
    private fun materialiseEnum(
        ast: TypeAst,
        category: CategoryPath,
        body: TypeDecl.Enum<GlobalTypeId>,
        explicitSizeBits: Int?,
    ): DataType {
        val sizeBytes = if (explicitSizeBits != null) (explicitSizeBits + 7) / 8 else 4
        val e = EnumDataType(category, ast.ghidraName, sizeBytes, dtm)
        for ((mname, mval) in body.members) e.add(mname, mval)
        return e
    }

    private fun materialiseBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType =
        when (val body = ast.body) {
            is TypeDecl.Pointer -> PointerDataType(
                dataTypeFor(body.pointee) ?: undef("body-pointer-pointee", ast.nameOrUnique, body.pointee),
                dtm.dataOrganization.pointerSize,
                dtm,
            )

            is TypeDecl.Reference -> PointerDataType(
                dataTypeFor(body.referent) ?: undef("body-reference-referent", ast.nameOrUnique, body.referent),
                dtm.dataOrganization.pointerSize,
                dtm,
            )

            is TypeDecl.Const -> dataTypeFor(body.inner) ?: placeholder

            is TypeDecl.Volatile -> dataTypeFor(body.inner) ?: placeholder

            // gcc emits anonymous nested aggregates as InlineDef(id, <aggregate body>);
            // dataTypeFor(body) picks up the harvested ast via tryGetExisting(body.id)
            // instead of hitting the null `referenced-aggregate` branch.
            is TypeDecl.InlineDef -> dataTypeFor(body)?.also {
                byId[body.id] = it
            } ?: placeholder

            is TypeDecl.Array -> {
                val elem = dataTypeFor(body.element) ?: run {
                    diagnostics.recordDegradation("array-element", ast.nameOrUnique, body.element.toString())
                    ByteDataType.dataType
                }
                recordXRefStubAt("array-element", ast.nameOrUnique, elem)
                val rangeLen = (body.indexType as? TypeDecl.Range)
                    ?.let { it.max - it.min + 1 }
                    ?.takeIf { it > 0 }
                val numElements = (body.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
                // ArrayDataType rejects length<1; FunctionDefinitionDataType reports
                // length=0. Substitute Undefined4 to preserve the array shape.
                val safeElem = if (elem.length < 1) {
                    diagnostics.recordDegradation(
                        "array-element-unsized",
                        ast.nameOrUnique,
                        "${elem::class.simpleName} has length ${elem.length}; substituted Undefined4",
                    )
                    Undefined4DataType.dataType
                } else {
                    elem
                }
                ArrayDataType(safeElem, numElements, safeElem.length)
            }

            is TypeDecl.Enum -> materialiseEnum(ast, category, body, explicitSizeBits = null)

            // `@s<bits>;e...;` — explicit enum size (stabs.texinfo §"String Field").
            is TypeDecl.WithSizeAttr if body.inner is TypeDecl.Enum ->
                materialiseEnum(ast, category, body.inner, explicitSizeBits = body.sizeBits)

            is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin ->
                BuiltinTable.resolve(body) ?: placeholder

            is TypeDecl.Struct -> {
                // Reuse the placeholder cast to the right type
                val struct: Composite = if (body.rawKind == AggrKind.UNION) {
                    placeholder as Union
                } else {
                    placeholder as Structure
                }

                // Insert base classes as inlined components.
                if (struct is Structure) {
                    // Layout boundary to infer size of unresolved bases: offset of next
                    // base or first non-static field is where this subobject must end.
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
                        // gcc's inheritance line doesn't transmit subobject size — derive
                        // from the consuming struct's own-field offset (CSymLexStream sees
                        // CLexStream as 192 bytes here even though canonical CLexStream is 328
                        // because another CU saw a richer definition).
                        val nextOffset =
                            sortedBaseOffsetsBytes.firstOrNull { it > offsetBytes } ?: firstFieldOffsetBytes
                        val gap = nextOffset - offsetBytes

                        // Empty placeholders report length=1 (Ghidra's enforced minimum);
                        // isZeroLength gives the logical truth. Treat as unresolved.
                        if (dt != null && !dt.isZeroLength && dt.length > 0 && dt.length <= gap) {
                            dataTypeByOffset[offsetBytes] = dt
                            resolvedBaseInfo[offsetBytes] = ResolvedBase(dt.name, dt.length)
                            continue
                        }

                        // Either unresolved or larger-than-gap (cross-CU size disagreement).
                        // Synthesise a gap-sized placeholder so own fields don't have to
                        // clear half of an oversized base.
                        if (gap <= 0) {
                            // Empty Base Optimization: subobject takes 0 bytes. Resolved-to-empty
                            // (std::allocator<char> in _Alloc_hider) or unresolved-but-gap-zero
                            // (libstdc++ iterator-tag bases living in headers). Skip insertion;
                            // own fields at offset 0 take the slot.
                            if (dt == null) {
                                log("base-empty-ebo-inferred")
                            } else {
                                log("base-empty-ebo")
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
                            "${ast.nameOrUnique}@+$offsetBytes",
                            reason,
                        )
                    }

                    // Skip synthesised placeholders (`unknown_<off>`): leave as Ghidra's
                    // default Undefined1 fill instead of pretending to be a real base.
                    // The `base-synthesized` degradation already records the diagnostic.
                    val ops = body.bases
                        .sortedBy { it.offsetBits }
                        .mapNotNull { base ->
                            val off = (base.offsetBits / 8).toInt()
                            val info = resolvedBaseInfo[off] ?: return@mapNotNull null
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
                            log("inheritance-applied")
                        } catch (e: java.lang.IllegalArgumentException) {
                            diagnostics.recordDegradation(
                                "base-layout-failed",
                                "${ast.nameOrUnique}::${op.baseSimpleName}",
                                e.message,
                            )
                            log("inheritance-failed")
                        }
                    }
                }

                val polyBase = ClassBuilderHelpers(resolver).firstPolymorphicBase(body)

                // Any vptr at a base-occupied offset is inherited — base owns it. Skip it.
                // Catches the unresolved-base case (synthesised _base_unknown_*) where
                // firstPolymorphicBase returns null but gcc still emitted _vptr$Class at
                // the base's offset (CLexStream → ios_base cascade).
                val baseOffsets = body.bases.map { it.offsetBits }.toSet()

                for (field in body.fields) {
                    if (field.isStatic) continue

                    val isParserEmittedVptr =
                        field.name.startsWith("_vptr$") || field.name.startsWith("_vptr.") || field.name == "_vptr"
                    if (
                        isParserEmittedVptr &&
                        (
                            (polyBase != null && field.offsetBits == polyBase.offsetBits) ||
                                field.offsetBits in baseOffsets
                            )
                    ) {
                        log("vptr-skipped-inherited")
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
                    // Zero-length placeholders report length=1 (Ghidra's enforced minimum).
                    // Use stab-declared bytes so the field occupies the right slot — otherwise
                    // we'd leave sizeBits/8 - 1 bytes as auto-Undefined holes.
                    val stabBytes = (field.sizeBits / 8).toInt()
                    val len = when {
                        ft.length <= 0 -> stabBytes.takeIf { it > 0 } ?: 4

                        ft.isZeroLength && stabBytes > 0 -> {
                            // Don't log when ft is a pre-seeded placeholder materialiseAll
                            // will fill in-place — same DTM object, mutating widens it to
                            // its real size. Only log untracked = real unresolvable XRef.
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
                            "${ast.nameOrUnique}.${field.name}",
                            e.message,
                        )
                    }
                }

                // Report runs ≥ 4 bytes of unnamed Undefined1 (Ghidra auto-fills empty bytes
                // with Undefined1 components so consecutive components are always contiguous —
                // a naive offset-gap detector never fires).
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
                            // ≥25% Undefined1 — catches the CSymLexStream "base invisible" pattern.
                            diagnostics.recordDegradation(
                                "struct-mostly-undefined",
                                "$category/${ast.ghidraName}",
                                "$bytesInHoles of $totalBytes bytes are unnamed Undefined1 across ${holes.size} run(s)",
                            )
                        }
                    }
                }

                // Plate-comment summary of base classes on the derived struct.
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
                // Alias to the canonical Struct for (kind, tagName). Without this,
                // gcc's ABI-internal typeinfo helpers (`__si_class_type_info_pseudo`)
                // emit `InlineDef(id, XRef(STRUCT,"Foo"))` and we'd materialise an
                // empty `XRef_[...]` Structure at the typeinfo location.
                // Resolver buckets its own degradations for failed lookups.
                resolver.lookupByXRef(body)
                    ?.let { canonical -> tryGetExisting(canonical.id)?.also { byId[ast.id] = it } }
                    ?: placeholder.also { xrefStubs.add(it) }
            }

            is TypeDecl.Ref -> tryGetExisting(body.id)
                ?: if (isVoidSelfRef(body.id) || body.id == ast.id) {
                    VoidDataType()
                } else {
                    diagnostics.recordDegradation(
                        "dangling-ref",
                        ast.nameOrUnique,
                        "ref to ${body.id} from ${ast.source}",
                    )
                    Undefined4DataType.dataType
                }
        }

    /**
     * Find a DataType by simple name across [allCreatedDataTypes]. Used by DemanglerReplacer
     * to match `/Demangler/std/string` stubs to our `/std/string`. Disambiguates by
     * [preferredCategory] when multiple match.
     */
    fun findByName(simpleName: String, preferredCategory: CategoryPath? = null): DataType? {
        val fromExtras = extrasByName[simpleName].orEmpty()
        // byId is GlobalTypeId-keyed, not name-indexed — linear scan for residual
        // aliases set via byId.putIfAbsent that didn't go through register(dt).
        val fromById = byId.values.filter { it.name == simpleName }
        val matches = (fromExtras + fromById).distinct()
        if (matches.isEmpty()) return null
        if (matches.size == 1) return matches.single()
        if (preferredCategory != null) {
            matches.firstOrNull { it.categoryPath == preferredCategory }?.let { return it }
        }
        log(
            "demangler-ambiguous",
            "Multiple matches for '$simpleName' (preferred=$preferredCategory): " +
                matches.joinToString { "${it.pathName}(${it::class.simpleName})" },
        )
        return null
    }
}

/**
 * Report runs of unnamed Undefined1 ≥ [minRunBytes] in a struct's component list.
 * Surfaces "couldn't render base subobject" / "undescribed padding" patterns. Each
 * triple is `(fieldName, (offsetBytes, lengthBytes), typeName)`.
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
