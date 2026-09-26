package ghistabs.materialize.cpp

import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghistabs.diagnose.DiagnosticSink
import ghistabs.index.LocatedType
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.reportHoles
import ghistabs.materialize.resolveRef
import ghistabs.materialize.undef
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.member
import java.util.IdentityHashMap
import ghidra.program.model.data.Array as GhidraArray

/**
 * A vptr at a base's offset is inherited: it is in the base subobject laid there, or in the non-virtual
 * part [layClasses] lays for a base with virtual bases of its own. Where no base could be laid, the
 * bytes stay undefined, so the stab's field is kept. A virtual base's offset is no position.
 */
internal fun DataTypeRegistry.inheritedVptrAt(
    body: TypeDecl.Aggregate<GlobalTypeId>,
    struct: Structure,
    offsetBits: Long,
): Boolean {
    val bases = body.bases.filter { !it.isVirtual && it.offsetBits == offsetBits }
    if (bases.isEmpty()) return false
    val at = (offsetBits / 8).toInt()
    return struct.definedComponents.any { at in it.offset..<it.offset + it.length } ||
        bases.any { hasVirtualBases(it.type) }
}

/** Null [TypeDecl.Method.cls] is gdb's stub method (`##<ret>;`) stating no domain — the normal gcc
 *  2.x encoding, not a failure; only a stated-but-unresolvable cls is a real loss. */
internal fun DataTypeRegistry.thisTypeFor(body: TypeDecl.Method<GlobalTypeId>, at: String): DataType =
    body.cls?.let { resolveRef(it) ?: undef("method-this-cls", at, it) } ?: Undefined4DataType.dataType

/**
 * `int A::*`: an Itanium data-member pointer is a byte offset, one ptrdiff_t wide, and Ghidra has no
 * pointer-to-member type. gcc ≤ 3.3 spells it as a pointer to the [TypeDecl.Member], ≥ 3.4 as
 * the Member alone (`build_ptrmem_type` stopped wrapping OFFSET_TYPE in POINTER_TYPE), so both
 * land here. The stab can't say which gcc wrote it, so ≥ 3.4's `int A::**` comes out one level
 * short — same width, so no layout moves.
 */
internal fun DataTypeRegistry.memberPointer(): DataType =
    // Unbound, like BuiltinTable's primitives: a program-bound `int` would fork `int.conflict`.
    AbstractIntegerDataType.getSignedDataType(dtm.dataOrganization.pointerSize, null)

/** [memberPointer] when a pointer to [pointee] is gcc ≤ 3.3's `int A::*`, else null. */
internal fun DataTypeRegistry.memberPointerTo(pointee: GlobalTypeDecl): DataType? =
    if (types.isMemberPointee(pointee)) memberPointer() else null

/**
 * Splices each non-virtual base's fields into [placeholder] at the offset the stab's inheritance line
 * gives it. Virtual bases, and bases with virtual bases of their own, are [layClasses]'s.
 */
internal fun DataTypeRegistry.fillStructBases(
    body: TypeDecl.Aggregate<GlobalTypeId>,
    placeholder: Structure,
    qualifiedName: String,
) {
    // An empty base occupies nothing (EBO) and must not be given the offset it shares with a
    // space-occupying sibling: cryptopp's `TwoBases<BlockCipher,Rijndael_Info>` declares both at +0,
    // and the empty one arriving second used to take the slot the 12-byte one had already claimed.
    val nonVirtual = body.bases.filterNot { it.isVirtual }
    val occupying = nonVirtual.filterNot { isEmptyBase(it.type) }
    if (occupying.size < nonVirtual.size) debug("base-empty-ebo")

    // Layout boundary to infer size of unresolved bases: offset of next
    // base or first non-static field is where this subobject must end.
    val sortedBaseOffsetsBytes = occupying.map { (it.offsetBits / 8).toInt() }.toSortedSet()
    val firstFieldOffsetBytes = body.fields
        .filter { !it.isStatic }
        .minOfOrNull { (it.offsetBits / 8).toInt() }
        ?: body.sizeBytes.toInt()

    for (base in occupying.filterNot { hasVirtualBases(it.type) }.sortedBy { it.offsetBits }) {
        val offsetBytes = (base.offsetBits / 8).toInt()
        // gcc's inheritance line doesn't transmit subobject size — derive
        // from the consuming struct's own-field offset (bouniaf sees
        // bouniaf as 192 bytes here even though canonical bouniaf is 328
        // because another CU saw a richer definition).
        val gap = (sortedBaseOffsetsBytes.firstOrNull { it > offsetBytes } ?: firstFieldOffsetBytes) - offsetBytes
        val raw = resolveRef(base.type)
        // Empty placeholders report length=1 (Ghidra's enforced minimum); isZeroLength gives the
        // logical truth. `dtm.contains` rejects a cycle-break stub, which [seedPlaceholder]
        // deliberately keeps out of the DTM: splicing one in makes `replaceAtOffset` resolve it on
        // the way in, forking a `.conflict` twin of a class we already built properly. Both are
        // "we have no base type here" for layout purposes.
        val dt = raw?.takeIf { dtm.contains(it) && !it.isZeroLength && it.length in 1..gap }
        if (dt == null) {
            // Unresolved, or larger-than-gap (cross-CU size disagreement). Leave the span as
            // Ghidra's default Undefined1 fill rather than name a subobject we can't stand behind.
            if (gap <= 0) {
                // Unresolved-but-gap-zero: libstdc++ iterator-tag bases living in headers this CU
                // only forward-declared. Own fields at offset 0 take the slot.
                debug("base-empty-ebo-inferred")
            } else {
                degradation(
                    "base-synthesized",
                    "$qualifiedName@+$offsetBytes",
                    if (raw == null || raw.isZeroLength || raw.length <= 0 || !dtm.contains(raw)) {
                        "Ref unresolved, $gap-byte subobject left undefined"
                    } else {
                        "${raw.name} (${raw.length}b) larger than gap ($gap b); left undefined"
                    },
                )
            }
            continue
        }
        placeBase(
            placeholder,
            offsetBytes,
            dt,
            base,
            ClassNaming.baseFieldName(false, dt.name, body.bases.size),
            qualifiedName,
        )
    }

    // Plate-comment summary of base classes on the derived struct.
    if (body.bases.isNotEmpty()) {
        val lines = body.bases.sortedBy { it.offsetBits }.joinToString("\n") { base ->
            val baseName = (resolveRef(base.type)?.name) ?: "<unresolved>"
            val at = if (base.isVirtual) " virtual $baseName" else " $baseName @ +${base.offsetBits / 8}"
            "inherits ${base.access.name.lowercase()}$at"
        }
        placeholder.description =
            if (placeholder.description.isNullOrEmpty()) lines else "${placeholder.description}\n$lines"
    }
}

private fun DataTypeRegistry.isEmptyBase(type: GlobalTypeDecl) =
    types.resolveStruct(type)?.sizeBytes?.let { it <= 1 } == true

internal fun DataTypeRegistry.hasVirtualBases(type: GlobalTypeDecl) =
    types.resolveStruct(type)?.let(types::hasVirtualBase) == true

private fun DataTypeRegistry.placeBase(
    struct: Structure,
    offset: Int,
    dt: DataType,
    base: TypeDecl.Aggregate.Base<GlobalTypeId>,
    fieldName: String,
    qualifiedName: String,
) {
    val (applied, failed) = if (base.isVirtual) {
        "vbase-applied" to "vbase-layout-failed"
    } else {
        "inheritance-applied" to
            "base-layout-failed"
    }
    runCatching { struct.replaceAtOffset(offset, dt, dt.length, fieldName, ClassNaming.baseComment(base)) }
        .onSuccess { debug(applied) }
        .onFailure {
            degradation(failed, qualifiedName.member(dt.name), it.message)
            if (!base.isVirtual) debug("inheritance-failed")
        }
}

internal val LocatedType.classBody get() = type.body as TypeDecl.Aggregate<GlobalTypeId>
internal val LocatedType.className get() = location.name

/**
 * Every located C++ class, bases before the classes that embed or derive from them: a class's layout
 * reads its bases' finished ones, and SPLIT_BASE reads a base's own placed `{vfptr}`.
 */
internal fun DataTypeRegistry.classesBasesFirst(): List<LocatedType> {
    val depthMemo = IdentityHashMap<TypeDecl.Aggregate<GlobalTypeId>, Int>()
    return byLocation.values
        .filter { (it.type.body as? TypeDecl.Aggregate)?.hasCxxSurface == true }
        .sortedBy { types.inheritanceDepth(it.classBody, depthMemo) }
}

/**
 * Where each virtual base goes in a complete object: after the non-virtual data ending at [nvEnd],
 * in order, each at the next offset its alignment allows. [vbases] are `(size, alignment)` pairs.
 * Null when that layout does not end at [completeSize] once rounded to the class's alignment. The
 * stab states the complete size but not where any virtual base is, so the size is the only check,
 * and a mismatch means the layout here is not the compiler's (a nearly-empty primary virtual base,
 * tail padding reused).
 */
fun virtualBaseOffsets(nvEnd: Int, nvAlign: Int, vbases: List<Pair<Int, Int>>, completeSize: Int): List<Int>? {
    var end = nvEnd
    val offsets = vbases.map { (size, align) -> alignUp(end, align).also { end = it + size } }
    val align = (vbases.map { it.second } + nvAlign).max()
    return offsets.takeIf { alignUp(end, align) == completeSize }
}

private fun alignUp(n: Int, align: Int) = (n + align - 1) / align * align

/**
 * The layout of every class that [fillStructBases] could not finish alone, bases before the classes
 * that embed them. A class with a virtual base in its graph gets its virtual half: a virtual base is
 * not where its inheritance line says (gcc ≥ 3.0 writes where in the *vtable* its offset can be found,
 * `!1,12-96,` being −12 bytes; gcc 2.x writes 0 and reaches the base through a `_vb$` field), so it is
 * laid once, in the complete object, after the non-virtual data, and a class embedded as a base
 * contributes only its non-virtual part. With a [VfptrModel], a polymorphic class then gets its `{vfptr}`.
 *
 * A class is final once its turn is over: nothing later writes into a base, so the non-virtual part a
 * derived class embeds is copied from a finished class.
 */
internal fun DataTypeRegistry.layClasses(vfptrModel: VfptrModel?) =
    ClassLayout(this, vfptrModel?.let { VfptrPlacement(this, it) }).layAll()

private class ClassLayout(val registry: DataTypeRegistry, val vfptrs: VfptrPlacement?) : DiagnosticSink by registry {
    private val types = registry.types

    /** The non-virtual size of each class laid here with virtual bases. */
    private val nonVirtualSizes = IdentityHashMap<DataType, Int>()

    /** Each embedded class's non-virtual part, as a struct of its own. */
    private val selfBases = IdentityHashMap<DataType, Structure>()

    fun layAll() {
        val laid = IdentityHashMap<Structure, Unit>()
        for (located in registry.classesBasesFirst()) {
            val struct = registry.dataTypeFor(located.type.id) as? Structure ?: continue
            runCatching {
                // Two locations can fill one struct (`/stabs/basic_ostream<…>` and `/std/basic_ostream<…>`),
                // and a second pass would take the laid virtual base for own data.
                if (laid.put(struct, Unit) == null && types.hasVirtualBase(located.classBody)) {
                    layVirtualInheritance(
                        located.classBody,
                        struct,
                        "${located.location.category}/${located.type.ghidraName}",
                    )
                }
                placeVfptr(located, struct)
            }.onFailure { err("class-layout-error", "${located.location}: ${it.message}") }
        }
    }

    private fun placeVfptr(located: LocatedType, struct: Structure) {
        val placement = vfptrs ?: return
        val hasPolyBase = types.hasPolymorphicBaseSubobject(located.classBody)
        if (!hasPolyBase && !located.classBody.declaresVptr) return
        placement.place(struct, located.className, located.classBody, hasPolyBase)
    }

    private fun layVirtualInheritance(
        body: TypeDecl.Aggregate<GlobalTypeId>,
        struct: Structure,
        qualifiedName: String,
    ) {
        embedNonVirtualParts(body, struct, qualifiedName)
        val nv = struct.definedComponents
        val nvEnd = nv.maxOfOrNull { it.offset + it.length } ?: 0
        val nvAlign = nv.maxOfOrNull { alignmentOf(it.dataType) } ?: 1
        layVirtualBases(body, struct, qualifiedName, nvEnd, nvAlign)
        nonVirtualSizes[struct] = alignUp(nvEnd, nvAlign)
        registry.reportHoles(struct, qualifiedName)
    }

    /** The non-virtual bases [fillStructBases] skipped because they have virtual bases of their own. */
    private fun embedNonVirtualParts(body: TypeDecl.Aggregate<GlobalTypeId>, struct: Structure, qualifiedName: String) {
        for (base in body.bases.filter { !it.isVirtual && registry.hasVirtualBases(it.type) }) {
            val offset = (base.offsetBits / 8).toInt()
            val dt = registry.resolveRef(base.type)?.let(::selfBaseOf) ?: run {
                degradation(
                    "base-synthesized",
                    "$qualifiedName@+$offset",
                    "no non-virtual part for ${base.type}; left undefined",
                )
                continue
            }
            val clash = struct.definedComponents.firstOrNull {
                offset < it.offset + it.length &&
                    it.offset < offset + dt.length
            }
            if (clash != null) {
                degradation(
                    "base-synthesized",
                    "$qualifiedName@+$offset",
                    "${dt.name} (${dt.length}b) overlaps ${clash.fieldName}; left undefined",
                )
                continue
            }
            registry.placeBase(
                struct,
                offset,
                dt,
                base,
                ClassNaming.baseFieldName(false, dt.name, body.bases.size),
                qualifiedName,
            )
        }
    }

    private fun layVirtualBases(
        body: TypeDecl.Aggregate<GlobalTypeId>,
        struct: Structure,
        qualifiedName: String,
        nvEnd: Int,
        nvAlign: Int,
    ) {
        val vbases = types.virtualBases(body)
            .mapNotNull { base -> registry.resolveRef(base.type)?.let { base to it } }
            .distinctBy { (_, dt) -> dt }
            .filterNot { (base, dt) -> dt.isZeroLength || registry.isEmptyBase(base.type) }
            .map { (base, dt) -> base to (selfBaseOf(dt) ?: dt) }
        val offsets = virtualBaseOffsets(
            nvEnd,
            nvAlign,
            vbases.map { (_, dt) -> dt.length to alignmentOf(dt) },
            body.sizeBytes.toInt(),
        ) ?: return degradation(
            "vbase-layout-mismatch",
            qualifiedName,
            "${vbases.joinToString {
                it.second.name
            }} after +$nvEnd does not end at ${body.sizeBytes} bytes; left undefined",
        )
        val count = body.bases.size + vbases.size
        for ((vbase, offset) in vbases.zip(offsets)) {
            val (base, dt) = vbase
            registry.placeBase(struct, offset, dt, base, ClassNaming.baseFieldName(true, dt.name, count), qualifiedName)
        }
    }

    /**
     * [cls] as a base subobject: its non-virtual part, without the virtual bases the most-derived class
     * lays for itself. Null for a class not laid here, which has no virtual base or never got that far.
     * Filed where Ghidra's PDB importer files a class's "self-base" ([ClassUtils.getBaseClassDataTypePath]),
     * and made only for a class something embeds.
     */
    private fun selfBaseOf(cls: DataType): Structure? {
        if (cls !is Structure) return null
        val size = nonVirtualSizes[cls] ?: return null
        return selfBases.getOrPut(cls) {
            val path = ClassUtils.getBaseClassDataTypePath(cls)
            registry.getOrRegister<Structure>(path.categoryPath, path.dataTypeName) {
                StructureDataType(path.categoryPath, path.dataTypeName, size, registry.dtm).apply {
                    description = "${cls.name} as a base subobject: its non-virtual part"
                }
            }.also { copyNonVirtualPart(cls, it) }
        }
    }

    private fun copyNonVirtualPart(from: Structure, into: Structure) {
        into.definedComponents.map { it.offset }.forEach(into::clearAtOffset)
        from.definedComponents
            .filter {
                it.offset + it.length <= into.length &&
                    !it.fieldName.orEmpty().startsWith(ClassNaming.VBASE_PREFIX)
            }
            .forEach {
                runCatching { into.replaceAtOffset(it.offset, it.dataType, it.length, it.fieldName, it.comment) }
            }
    }

    /** Natural alignment. Ours are non-packed structs, which Ghidra aligns at 1 whatever they hold. */
    private fun alignmentOf(dt: DataType): Int = when (dt) {
        is Composite -> dt.definedComponents.maxOfOrNull { alignmentOf(it.dataType) } ?: 1
        is GhidraArray -> alignmentOf(dt.dataType)
        is TypeDef -> alignmentOf(dt.baseDataType)
        else -> registry.dtm.dataOrganization.getAlignment(dt)
    }
}
