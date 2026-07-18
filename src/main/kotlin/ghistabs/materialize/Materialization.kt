package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.diagnose.degradation
import ghistabs.harvest.TypeAst
import ghistabs.materialize.itanium.*
import ghistabs.parse.*
import ghistabs.runTransaction
import ghidra.program.model.data.Enum as GhidraEnum

/**
 * Fill the pre-registered enum [placeholder] in place (its size was fixed at creation, see
 * [makePlaceholder]) and return it, so one DTM-resident Enum is both the cycle-break stub and
 * the final type — no colliding second copy. bool doesn't reach this path — it comes through
 * BuiltinTable slot -16.
 */
private fun materializeEnum(placeholder: GhidraEnum, body: TypeDecl.Enum<GlobalTypeId>): DataType {
    for ((mname, mval) in body.members) placeholder.add(mname, mval)
    return placeholder
}

internal fun TypeRegistry.materializeBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType =
    when (val body = ast.body) {
        is TypeDecl.Pointer -> pointerTo(body.pointee, "body-pointer-pointee", ast.ghidraName)

        is TypeDecl.Reference -> pointerTo(body.referent, "body-reference-referent", ast.ghidraName)

        // Transparent wrappers/primitives resolve through resolveRef (which unwraps const/volatile
        // and routes the builtin-family via BuiltinTable), falling back to the placeholder.
        is TypeDecl.Const, is TypeDecl.Volatile -> resolveRef(body) ?: placeholder

        // gcc emits anonymous nested aggregates as InlineDef(id, <aggregate body>);
        // resolveRef(body) picks up the harvested ast via getOrMaterialize(body.id)
        // instead of hitting the null `referenced-aggregate` branch.
        is TypeDecl.InlineDef -> resolveRef(body)?.also {
            byId[body.id] = it
        } ?: placeholder

        is TypeDecl.Array -> {
            val elem = resolveRef(body.element) ?: run {
                degradation("array-element", ast.ghidraName, body.element.toString())
                ByteDataType.dataType
            }
            recordXRefStubAt("array-element", ast.ghidraName, elem)
            val rangeLen = (body.indexType as? TypeDecl.Range)
                ?.let { it.max - it.min + 1 }
                ?.takeIf { it > 0 }
            val numElements = (body.length ?: rangeLen ?: 1L).toInt().coerceAtLeast(1)
            // ArrayDataType rejects length<1; FunctionDefinitionDataType reports
            // length=0. Substitute Undefined4 to preserve the array shape.
            val safeElem = if (elem.length < 1) {
                degradation(
                    "array-element-unsized",
                    ast.ghidraName,
                    "${elem::class.simpleName} has length ${elem.length}; substituted Undefined4",
                )
                Undefined4DataType.dataType
            } else {
                elem
            }
            ArrayDataType(safeElem, numElements, safeElem.length)
        }

        is TypeDecl.Enum -> materializeEnum(placeholder as GhidraEnum, body)

        // `@s<bits>;e...;` — explicit enum size (stabs.texinfo §"String Field"); size already
        // applied to the placeholder in makePlaceholder.
        is TypeDecl.WithSizeAttr if body.inner is TypeDecl.Enum ->
            materializeEnum(placeholder as GhidraEnum, body.inner)

        is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin ->
            resolveRef(body) ?: placeholder

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
                    val dt = resolveRef(base.type)
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
                            debug("base-empty-ebo-inferred")
                        } else {
                            debug("base-empty-ebo")
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
                    degradation(
                        "base-synthesized",
                        "${ast.ghidraName}@+$offsetBytes",
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
                        InsertOp(
                            offsetBytes = off,
                            fieldName = Layout.baseFieldName(base.isVirtual, info.simpleName),
                            comment = Layout.baseComment(base),
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
                        debug("inheritance-applied")
                    } catch (e: java.lang.IllegalArgumentException) {
                        degradation(
                            "base-layout-failed",
                            "${ast.ghidraName}::${op.baseSimpleName}",
                            e.message,
                        )
                        debug("inheritance-failed")
                    }
                }
            }

            val polyBase = resolver.firstPolymorphicBase(body)

            // Any vptr at a base-occupied offset is inherited — base owns it. Skip it.
            // Catches the unresolved-base case (synthesised _base_unknown_*) where
            // firstPolymorphicBase returns null but gcc still emitted _vptr$Class at
            // the base's offset (CLexStream → ios_base cascade).
            val baseOffsets = body.bases.map { it.offsetBits }.toSet()

            for (field in body.fields) {
                if (field.isStatic) continue

                if (
                    Itanium.isVptrField(field.name) &&
                    (
                        (polyBase != null && field.offsetBits == polyBase.offsetBits) ||
                            field.offsetBits in baseOffsets
                        )
                ) {
                    debug("vptr-skipped-inherited")
                    continue
                }

                val resolvedFt = resolveRef(field.type)
                val ft = resolvedFt
                    ?: undef("field-type", "${ast.ghidraName}.${field.name}", field.type)
                if (resolvedFt != null && resolvedFt.name.startsWith("undefined")) {
                    degradation(
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
                        // Don't log when ft is a pre-seeded placeholder materializeAll
                        // will fill in-place — same DTM object, mutating widens it to
                        // its real size. Only log untracked = real unresolvable XRef.
                        if (ft !in placeholders.values) {
                            degradation(
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
                    degradation(
                        "field-dropped",
                        "${ast.ghidraName}.${field.name}",
                        e.message,
                    )
                }
            }

            // Report runs ≥ 4 bytes of unnamed Undefined1 (Ghidra auto-fills empty bytes
            // with Undefined1 components so consecutive components are always contiguous —
            // a naive offset-gap detector never fires).
            if (struct is Structure) {
                val holes = struct.detectUndefinedRuns(minRunBytes = 4)
                val qualifiedName = "$category/${ast.ghidraName}"
                diagnostics.recordStructGaps(qualifiedName, holes)
                if (holes.isNotEmpty()) {
                    val bytesInHoles = holes.sumOf { (it.lengthBits / 8).toInt() }
                    val totalBytes = struct.length
                    if (totalBytes > 0 && bytesInHoles * 4 >= totalBytes) {
                        // ≥25% Undefined1 — catches the CSymLexStream "base invisible" pattern.
                        degradation(
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
                    val baseName = (resolveRef(base.type)?.name) ?: "<unresolved>"
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
            thisType = resolveRef(body.cls) ?: undef("method-this-cls", ast.ghidraName, body.cls),
            callingConvention = "__thiscall",
            at = ast.ghidraName,
        )

        // Alias to the canonical Struct for (kind, tagName). Without this,
        // gcc's ABI-internal typeinfo helpers (`__si_class_type_info_pseudo`)
        // emit `InlineDef(id, XRef(STRUCT,"Foo"))` and we'd materialize an
        // empty `XRef_[...]` Structure at the typeinfo location.
        // Resolver buckets its own degradations for failed lookups.
        is TypeDecl.XRef -> resolver.lookupByXRef(body)
            ?.let { canonical -> getOrMaterialize(canonical.id)?.also { byId[ast.id] = it } }
            ?: placeholder.also { xrefStubs.add(it) }

        is TypeDecl.Ref -> getOrMaterialize(body.id)
            ?: if (ast.isVoidSelfRef()) {
                VoidDataType()
            } else {
                degradation(
                    "dangling-ref",
                    ast.ghidraName,
                    "ref to ${body.id} from ${ast.source}",
                )
                Undefined4DataType.dataType
            }
    }

private fun TypeRegistry.undef(category: String, at: String, decl: TypeDecl<GlobalTypeId>): DataType {
    degradation(category, at, decl.toString())
    return Undefined4DataType.dataType
}

/**
 * Pointer/reference construction shared by [resolveRef] (reference sites) and [materializeBody]
 * (definition sites): wrap the resolved [pointee] in a target-sized [PointerDataType], degrading to
 * [undef] under the caller's [label]/[at] when the pointee doesn't resolve.
 */
private fun TypeRegistry.pointerTo(pointee: TypeDecl<GlobalTypeId>, label: String, at: String): PointerDataType =
    PointerDataType(resolveRef(pointee) ?: undef(label, at, pointee), dtm.dataOrganization.pointerSize, dtm)

/** gcc/gdb (stabsread.c): `Ref(self.id)` encodes void — used for void returns and method-args sentinel. */
internal fun TypeAst.isVoidSelfRef(): Boolean = body is TypeDecl.Ref && body.id == id

/**
 * Resolve a TypeDecl reference site to a DataType. Struct/Enum/Method/XRef return null (they
 * only have identity through their owning TypeAst id; use [TypeRegistry.getOrMaterialize] for those).
 */
fun TypeRegistry.resolveRef(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
    is TypeDecl.Ref -> getOrMaterialize(decl.id)
        ?: if (harvest.getType(decl.id)?.isVoidSelfRef() == true) VoidDataType() else null

    is TypeDecl.InlineDef -> {
        getOrMaterialize(decl.id) ?: resolveRef(decl.body)?.apply {
            byId[decl.id] = this
        }
    }

    is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.WithSizeAttr, is TypeDecl.Builtin -> {
        BuiltinTable.resolve(decl)
    }

    is TypeDecl.Pointer -> pointerTo(decl.pointee, "pointer-pointee", "(anon)")

    is TypeDecl.Reference -> pointerTo(decl.referent, "reference-referent", "(anon)")

    is TypeDecl.Const -> resolveRef(decl.inner)

    is TypeDecl.Volatile -> resolveRef(decl.inner)

    is TypeDecl.Array -> {
        // ByteDataType (not Undefined1) for unresolved elements: Undefined1 is
        // type-equivalent to Ghidra's auto-analysis "undefined" bytes, so a downstream
        // data-ref analyzer will recoalesce our array into `undefined4`.
        val elem = resolveRef(decl.element) ?: ByteDataType.dataType
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

    // XRef → canonical TypeAst by (kind, tagName), then materialized DataType
    // by id. Unified across struct/union/class/enum.
    is TypeDecl.XRef -> resolver.byXRef(decl)?.let { getOrMaterialize(it.id) }

    // Aggregate bodies — meaningful only via owning TypeId; see kdoc.
    is TypeDecl.Struct, is TypeDecl.Enum, is TypeDecl.Method -> {
        debug("referenced-aggregate", "asked for ref to $decl")
        null
    }
}

/**
 * Build a FunctionDefinition (not yet added to DTM) from stab types. Resolves
 * [ret]/[params] via [resolveRef], handles gcc's void-sentinel arg-list terminator,
 * and applies [callingConvention] if the program's CompilerSpec accepts it.
 */
fun TypeRegistry.buildFunctionDefinition(
    category: CategoryPath,
    name: String,
    ret: TypeDecl<GlobalTypeId>,
    params: List<TypeDecl<GlobalTypeId>>,
    thisType: DataType? = null,
    callingConvention: String? = null,
    at: String = name,
): FunctionDefinitionDataType {
    val fd = FunctionDefinitionDataType(category, name, dtm)
    fd.returnType = resolveRef(ret) ?: run {
        degradation("function-ret-untyped", at, ret.toString())
        VoidDataType()
    }
    // gcc method signatures end in a void sentinel; passing it would trip
    // ParameterDefinitionImpl's "void type not permitted" assertion. Drop the
    // trailing void; substitute Undefined4 mid-list to keep arity stable.
    val effectiveParams = if (params.isNotEmpty() && resolveRef(params.last()) is VoidDataType) {
        params.dropLast(1)
    } else {
        params
    }
    // gcc `#` method form puts `this` AS THE FIRST PARAM (gdb stabsread.c::read_args:
    // "We should read at least the THIS parameter here."). When [thisType] is set we
    // just name the first param `this`.
    val argDefs = effectiveParams.mapIndexed { i, p ->
        val resolved = resolveRef(p) ?: undef("function-param", "$at[$i]", p)
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

fun TypeRegistry.materializeAll() {
    // Two phases: (1) materialize each CanonicalGroup winner into its (cat,name)
    // slot and alias members to it; (2) non-registerable top-level asts
    // (FunctionT, Method, XRef aliases) via materializeTopLevel() — byId only, no DTM slot.
    dtm.runTransaction("ghidra-stabs build types") {
        val memberToWinner = resolver.byCanonicalKey.values.flatMap { g -> g.members.map { it to g.ast } }.toMap()
        val winnerCategory = resolver.byCanonicalKey.values.associate { it.ast.id to it.key.category }

        // Pre-seed placeholders for every member id so Ref(id) cycle-breaks during
        // body materialization. Struct/Union and Enum placeholders go into the DTM
        // up-front so later in-place mutations land on the DTM-resident object — and a
        // Ref resolved before the winner materializes pulls in that one object, not an
        // empty second copy that would collide with the filled type (`.conflict`).
        for (group in resolver.byCanonicalKey.values) {
            val winner = group.ast
            val raw = makePlaceholder(winner, group.key.category, name = group.key.name)
            val placeholder =
                if (winner.body is TypeDecl.Struct || raw is GhidraEnum) register(raw) else raw
            for (m in group.members) placeholders.putIfAbsent(m, placeholder)
        }

        monitor.initialize(winnerCategory.size.toLong(), "Stabs: materializing types")
        for ((winnerId, category) in winnerCategory) {
            monitor.increment()
            val winner = harvest.getType(winnerId) ?: continue
            val placeholder = placeholders[winnerId]!!
            val materialized = materializeBody(winner, category, placeholder)
            if (materialized === placeholder) {
                byId[winnerId] = placeholder
            } else {
                register(materialized, winnerId)
            }
        }
        for ((memberId, winner) in memberToWinner) {
            byId[winner.id]?.let { byId.putIfAbsent(memberId, it) }
        }

        registerNamedPrimitiveTypedefs()

        // Non-registerable top-level typeAsts (XRef body, FunctionT, Method, …)
        for (ast in harvest.typeAsts.values) {
            if (ast.id in byId) continue
            materializeTopLevel(ast)
        }
    }
}

/**
 * Named primitive typedefs ("unsigned int", "char", …) — not XRefTargets so absent from
 * byCanonicalKey, but stabs gives them names worth exposing as typedef aliases. Grouped by
 * ghidraName for one typedef per logical name.
 */
private fun TypeRegistry.registerNamedPrimitiveTypedefs() {
    harvest.typeAsts.values
        .filter { it.name != null && !it.body.isXRefTarget }
        .groupBy { it.ghidraName }
        .forEach { (ghidraName, asts) ->
            // Per-ast resolution: one CU emits `bool:t=_Bool` (1B), another
            // `bool:t=int` (4B). Sharing one typedef across all ids would
            // produce wrong field sizes and `bool.conflict` in the DTM.
            for (ast in asts) {
                val resolved = BuiltinTable.resolve(ast.body) ?: resolveRef(ast.body) ?: continue
                byId.putIfAbsent(ast.id, resolved)
            }
            // One shared typedef under /stabs (or root for primitives) for
            // DemanglerReplacer to substitute into `/Demangler/*` stubs.
            val firstBody = asts.first().body
            val typedefTarget = BuiltinTable.resolve(firstBody) ?: resolveRef(firstBody) ?: return@forEach
            // §20: when the target already carries this exact name (a `typedef struct {…}
            // Name;` whose anonymous aggregate we named after the typedef, then merged with
            // the named copy), a same-named `/stabs` typedef is just a second DataType with
            // the identical name. Ghidra resolves a struct/enum's display name across all
            // same-named DataTypes, so the duplicate destabilises it — the named type suffices.
            if (typedefTarget.name == ghidraName) return@forEach
            val category = if (BuiltinTable.resolve(firstBody) != null) {
                CategoryPath.ROOT
            } else {
                CATEGORY
            }
            register(TypedefDataType(category, ghidraName, typedefTarget, dtm))
        }
}

/** Materialize a non-registerable top-level ast (XRef alias, FunctionT, Method). */
internal fun TypeRegistry.materializeTopLevel(ast: TypeAst): DataType {
    // RTTI pseudo-types and primitives resolve to their authoritative layout — a final type, so it
    // must not fall through to the XRef-stub path below (which would file it under xrefStubs and
    // flag every _ZTI global as a `degraded-*-typed-xref-stub` false alarm).
    substitute(ast)?.let {
        byId[ast.id] = it
        return it
    }
    if (ast.body is TypeDecl.XRef) {
        resolver.byXRef(ast.body)?.let { canonical ->
            val dt = byId[canonical.id] ?: materializeTopLevel(canonical)
            byId[ast.id] = dt
            return dt
        }
    }
    // Void self-ref: resolve before any placeholder is created, otherwise
    // getOrMaterialize returns the placeholder and the VoidDataType fallback never fires.
    if (ast.body is TypeDecl.Ref && ast.body.id == ast.id) {
        val void = VoidDataType()
        byId[ast.id] = void
        return void
    }
    val placeholder = placeholders.getOrPut(ast.id) {
        makePlaceholder(ast, CATEGORY, "ref-stub")
    }
    return materializeBody(ast, CATEGORY, placeholder).also { materialized ->
        byId.putIfAbsent(ast.id, materialized)
    }
}
