package ghistabs.materialize

import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.inheritanceDepth
import ghistabs.materialize.cpp.virtualBases
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import java.util.IdentityHashMap
import ghidra.program.model.data.Array as GhidraArray

/** A class [fillComposite] left for [layVirtualInheritance]: one with a virtual base somewhere in its graph. */
internal data class VirtualLayout(
    val body: TypeDecl.Aggregate<GlobalTypeId>,
    val struct: Structure,
    val qualifiedName: String,
)

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
 * The virtual half of inheritance, once every struct is filled and bases before the classes that
 * embed them, since each class needs its bases' non-virtual parts. A virtual base is not where its
 * inheritance line says: gcc ≥ 3.0 writes where in the *vtable* its offset can be found (`!1,12-96,`
 * is −12 bytes), gcc 2.x writes 0 and reaches the base through a `_vb$` field. It is laid once, in
 * the complete object, after the non-virtual data; a class embedded as a base contributes only its
 * non-virtual part.
 */
internal fun DataTypeRegistry.layVirtualInheritance() {
    val memo = IdentityHashMap<TypeDecl.Aggregate<GlobalTypeId>, Int>()
    for ((body, struct, qualifiedName) in virtualLayouts.values.sortedBy { types.inheritanceDepth(it.body, memo) }) {
        embedNonVirtualParts(body, struct, qualifiedName)
        val nv = struct.definedComponents
        val nvEnd = nv.maxOfOrNull { it.offset + it.length } ?: 0
        val nvAlign = nv.maxOfOrNull { alignmentOf(it.dataType) } ?: 1
        layVirtualBases(body, struct, qualifiedName, nvEnd, nvAlign)
        nonVirtualSizes[struct] = alignUp(nvEnd, nvAlign)
        reportHoles(struct, qualifiedName)
    }
}

/** The non-virtual bases [fillStructBases] skipped because they have virtual bases of their own. */
private fun DataTypeRegistry.embedNonVirtualParts(
    body: TypeDecl.Aggregate<GlobalTypeId>,
    struct: Structure,
    qualifiedName: String,
) {
    for (base in body.bases.filter { !it.isVirtual && hasVirtualBases(it.type) }) {
        val offset = (base.offsetBits / 8).toInt()
        val dt = resolveRef(base.type)?.let(::selfBaseOf)
        val clash = dt?.let {
            struct.definedComponents.firstOrNull { c ->
                c.offset < offset + it.length &&
                    offset < c.offset + c.length
            }
        }
        if (dt == null || clash != null) {
            degradation(
                "base-synthesized",
                "$qualifiedName@+$offset",
                clash?.let { "${dt?.name} (${dt?.length}b) overlaps ${it.fieldName}; left undefined" }
                    ?: "no non-virtual part for ${base.type}; left undefined",
            )
            continue
        }
        runCatching {
            struct.replaceAtOffset(
                offset,
                dt,
                dt.length,
                ClassNaming.baseFieldName(false, dt.name, body.bases.size),
                ClassNaming.baseComment(base),
            )
        }.onSuccess { debug("inheritance-applied") }
            .onFailure { degradation("base-layout-failed", "$qualifiedName::${dt.name}", it.message) }
    }
}

private fun DataTypeRegistry.layVirtualBases(
    body: TypeDecl.Aggregate<GlobalTypeId>,
    struct: Structure,
    qualifiedName: String,
    nvEnd: Int,
    nvAlign: Int,
) {
    val vbases = types.virtualBases(body)
        .mapNotNull { base -> resolveRef(base.type)?.let { base to it } }
        .distinctBy { (_, dt) -> dt }
        .filterNot { (base, dt) ->
            dt.isZeroLength || types.resolveStruct(base.type)?.sizeBytes?.let { it <= 1 } == true
        }
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
        runCatching {
            struct.replaceAtOffset(
                offset,
                dt,
                dt.length,
                ClassNaming.baseFieldName(true, dt.name, count),
                ClassNaming.baseComment(base),
            )
        }.onSuccess { debug("vbase-applied") }
            .onFailure { degradation("vbase-layout-failed", "$qualifiedName::${dt.name}", it.message) }
    }
}

/**
 * [cls] as a base subobject: its non-virtual part, without the virtual bases the most-derived class
 * lays for itself. Null for a class [layVirtualInheritance] has not laid, which has no virtual base or
 * never got that far. Filed where Ghidra's PDB importer files a class's "self-base"
 * ([ClassUtils.getBaseClassDataTypePath]), and made only for a class something embeds.
 */
private fun DataTypeRegistry.selfBaseOf(cls: DataType): Structure? {
    if (cls !is Structure) return null
    val size = nonVirtualSizes[cls] ?: return null
    return selfBases.getOrPut(cls) {
        val path = ClassUtils.getBaseClassDataTypePath(cls)
        getOrRegister<Structure>(path.categoryPath, path.dataTypeName) {
            StructureDataType(path.categoryPath, path.dataTypeName, size, dtm).apply {
                description = "${cls.name} as a base subobject: its non-virtual part"
            }
        }.also { copyNonVirtualPart(cls, it) }
    }
}

internal fun DataTypeRegistry.hasVirtualBases(type: GlobalTypeDecl) =
    types.resolveStruct(type)?.let { types.virtualBases(it).isNotEmpty() } == true

/**
 * Brings [cls]'s self-base back in line with [cls], which the class pass changes after
 * [layVirtualInheritance] copied it (the vfptr it places, the base it splits).
 */
internal fun DataTypeRegistry.syncSelfBase(cls: Structure) {
    selfBases[cls]?.let { copyNonVirtualPart(cls, it) }
}

/** Components are replaced rather than the struct rebuilt: a length change would ripple into every
 *  class already embedding [into]. */
private fun copyNonVirtualPart(from: Structure, into: Structure) {
    into.definedComponents.map { it.offset }.forEach(into::clearAtOffset)
    from.definedComponents
        .filter { it.offset + it.length <= into.length && !it.fieldName.orEmpty().startsWith(ClassNaming.VBASE_PREFIX) }
        .forEach { runCatching { into.replaceAtOffset(it.offset, it.dataType, it.length, it.fieldName, it.comment) } }
}

/** Natural alignment. Ours are non-packed structs, which Ghidra aligns at 1 whatever they hold. */
private fun DataTypeRegistry.alignmentOf(dt: DataType): Int = when (dt) {
    is Composite -> dt.definedComponents.maxOfOrNull { alignmentOf(it.dataType) } ?: 1
    is GhidraArray -> alignmentOf(dt.dataType)
    is TypeDef -> alignmentOf(dt.baseDataType)
    else -> dtm.dataOrganization.getAlignment(dt)
}
