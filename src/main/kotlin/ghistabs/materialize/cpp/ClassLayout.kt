package ghistabs.materialize.cpp

import ghidra.program.model.data.Structure
import ghistabs.diagnose.DiagnosticSink
import ghistabs.index.LocatedType
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.resolveRef
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.member

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
    val occupying = body.bases.filterNot { types.resolveStruct(it.type)?.sizeBytes?.let { n -> n <= 1 } == true }
    if (occupying.size < body.bases.size) debug("base-empty-ebo")

    // Layout boundary to infer size of unresolved bases: offset of next
    // base or first non-static field is where this subobject must end.
    val sortedBaseOffsetsBytes = occupying.map { (it.offsetBits / 8).toInt() }.toSortedSet()
    val firstFieldOffsetBytes = body.fields
        .filter { !it.isStatic }
        .minOfOrNull { (it.offsetBits / 8).toInt() }
        ?: body.sizeBytes.toInt()

    for (base in occupying.sortedBy { it.offsetBits }) {
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
        runCatching {
            placeholder.replaceAtOffset(
                offsetBytes,
                dt,
                dt.length,
                ClassNaming.baseFieldName(base.isVirtual, dt.name, body.bases.size),
                ClassNaming.baseComment(base),
            )
        }.onSuccess { debug("inheritance-applied") }
            .onFailure {
                degradation("base-layout-failed", qualifiedName.member(dt.name), it.message)
                debug("inheritance-failed")
            }
    }

    // Plate-comment summary of base classes on the derived struct.
    if (body.bases.isNotEmpty()) {
        val lines = body.bases.sortedBy { it.offsetBits }.joinToString("\n") { base ->
            val baseName = (resolveRef(base.type)?.name) ?: "<unresolved>"
            val virt = if (base.isVirtual) " virtual" else ""
            "inherits ${base.access.name.lowercase()}$virt $baseName @ +${base.offsetBits / 8}"
        }
        placeholder.description =
            if (placeholder.description.isNullOrEmpty()) lines else "${placeholder.description}\n$lines"
    }
}

internal val LocatedType.classBody get() = type.body as TypeDecl.Aggregate<GlobalTypeId>
internal val LocatedType.className get() = location.name

/**
 * Every located C++ class, bases before the classes that embed or derive from them: a class's layout
 * reads its bases' finished ones, and SPLIT_BASE reads a base's own placed `{vfptr}`.
 */
internal fun DataTypeRegistry.classesBasesFirst(): List<LocatedType> {
    val depthMemo = mutableMapOf<GlobalTypeDecl, Int>()
    return byLocation.values
        .filter { (it.type.body as? TypeDecl.Aggregate)?.hasCxxSurface == true }
        .sortedBy { types.inheritanceDepth(it.classBody, depthMemo) }
}

/**
 * Gives each polymorphic class its `{vfptr}`, bases before the classes that derive from them:
 * SPLIT_BASE reads a base's own placed `{vfptr}`. Only with a [VfptrModel], i.e. when classes are
 * built. Runs after typedef shortening: the vftables and `_fields_` structs it creates are looked
 * up again by name.
 */
internal fun DataTypeRegistry.layClasses(vfptrModel: VfptrModel?) =
    ClassLayout(this, vfptrModel?.let { VfptrPlacement(this, it) }).layAll()

private class ClassLayout(val registry: DataTypeRegistry, val vfptrs: VfptrPlacement?) : DiagnosticSink by registry {
    private val types = registry.types

    fun layAll() {
        for (located in registry.classesBasesFirst()) {
            val struct = registry.dataTypeFor(located.type.id) as? Structure ?: continue
            runCatching {
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
}
