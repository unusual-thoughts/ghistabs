package ghistabs.materialize.itanium

import ghistabs.harvest.HarvestIndex
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Struct.Base
import ghistabs.parse.TypeDecl.Struct.Method
import ghistabs.parse.VirtKind

/** Component snapshot at a target offset, fed into vfptr placement decisions. */
data class FirstComponentSnapshot(val fieldName: String?, val offsetBytes: Int, val isUndefined: Boolean)

sealed class VfptrAction {
    object SkipInheritedFromBase : VfptrAction()
    data class Insert(val offsetBytes: Int) : VfptrAction()
    data class Replace(val offsetBytes: Int, val wasFieldName: String) : VfptrAction()
    object AlreadyCanonical : VfptrAction()
    data class CollisionAt(val offsetBytes: Int, val occupantFieldName: String) : VfptrAction()
}

/** Pure C++ record-layout decisions: where the vfptr goes and how base subobjects are spliced in. */
object Layout {
    /** Extracted from `ClassBuilder.ensureVfptrFirstField` for pure unit testing. */
    fun chooseVfptrAction(
        hasPolymorphicBaseSubobject: Boolean,
        parserVptrOffsetBytes: Int?,
        componentAtTargetOffset: FirstComponentSnapshot?,
        canonicalVfptrFieldName: String,
    ): VfptrAction {
        if (hasPolymorphicBaseSubobject) return VfptrAction.SkipInheritedFromBase

        val targetOffset = parserVptrOffsetBytes ?: 0

        if (
            componentAtTargetOffset != null &&
            componentAtTargetOffset.offsetBytes == targetOffset &&
            componentAtTargetOffset.fieldName == canonicalVfptrFieldName
        ) {
            return VfptrAction.AlreadyCanonical
        }

        if (componentAtTargetOffset == null || componentAtTargetOffset.isUndefined) {
            return VfptrAction.Insert(targetOffset)
        }

        // Catches the unresolved/synthesized-base case where polymorphism couldn't be proven
        // but the stab layout still puts a base at the vptr offset — base owns the vfptr.
        if (componentAtTargetOffset.fieldName?.let(Itanium::isBaseField) == true) {
            return VfptrAction.SkipInheritedFromBase
        }

        return if (componentAtTargetOffset.fieldName?.let(Itanium::isVptrField) == true) {
            VfptrAction.Replace(targetOffset, componentAtTargetOffset.fieldName)
        } else {
            VfptrAction.CollisionAt(targetOffset, componentAtTargetOffset.fieldName ?: "<anon>")
        }
    }

    fun baseFieldName(isVirtual: Boolean, simpleName: String, baseCount: Int) =
        (if (isVirtual) Itanium.VBASE_PREFIX else Itanium.BASE_PREFIX) + simpleName.takeIf { baseCount > 1 }.orEmpty()

    fun baseComment(base: Base<GlobalTypeId>) = buildString {
        append(base.access.name.lowercase())
        if (base.isVirtual) append(" virtual")
        append(" base")
    }
}

/** Does [typeDecl] inherit a vfptr from a polymorphic base subobject (vs. introducing its own)? */
fun HarvestIndex.hasPolymorphicBaseSubobject(typeDecl: TypeDecl.Struct<GlobalTypeId>) =
    firstPolymorphicBase(typeDecl) != null

/** Lowest-offset polymorphic base, or null. Determines whether to insert a vfptr or inherit. */
fun HarvestIndex.firstPolymorphicBase(typeDecl: TypeDecl.Struct<GlobalTypeId>): Base<GlobalTypeId>? = typeDecl.bases
    .sortedBy { it.offsetBits }
    .firstOrNull { base ->
        baseStructOf(base.type)?.run {
            hasVTablePointerMarker ||
                methods.any { it.virt == VirtKind.VIRTUAL } ||
                firstPolymorphicBase(this) != null
        } ?: false
    }

/**
 * Every virtual base in [typeDecl]'s graph, not only the directly-declared ones — a vtable carries one
 * vbase offset per *distinct* virtual base however deep it was inherited. `std::iostream` is the case
 * that forces it: `_ZTISd` declares `istream` and `ostream`, neither virtual, and `__ZTVSd` still has a
 * vbase offset, for the `basic_ios` both of them inherit virtually.
 *
 * Not folded into [Virtuals], which walks the same edges: that one wants each struct once, bases-first,
 * to collect methods, while this wants every *edge*, because a virtual edge to a class already reached
 * through a non-virtual one still contributes a vbase offset. One traversal serving both only reads as
 * a traversal with two modes.
 */
fun HarvestIndex.virtualBases(typeDecl: TypeDecl.Struct<GlobalTypeId>) = buildList {
    val seen = mutableSetOf<TypeDecl.Struct<GlobalTypeId>>()
    fun walk(cls: TypeDecl.Struct<GlobalTypeId>) {
        if (!seen.add(cls)) return
        for (base in cls.bases) {
            if (base.isVirtual) add(base)
            baseStructOf(base.type)?.let(::walk)
        }
    }
    walk(typeDecl)
}

/**
 * The struct body defining the base class [typeDecl] names, or null if it cannot be reached. Every
 * walk of the inheritance graph goes through here — vfptr inheritance, virtual collection,
 * vbase counting — because gcc spells the same base three ways depending on what the CU had already
 * emitted, and a caller that handled only one of them would silently see a class as having no bases:
 *
 * - `Ref(id)` — the ordinary case, the base was already defined; take the ast at that id.
 * - `XRef` — a forward declaration carrying only a tag name; find the ast that defines the tag.
 * - `InlineDef(id, inner)` — the definition spliced in at the point of use. Prefer the ast registered
 *   at the id over `inner`, which is frequently itself a forward `XRef`: without that preference
 *   polymorphism detection misses inherited vfptrs (`bouniaf` → `InlineDef(ExprInst id, XRef body)`).
 */
fun HarvestIndex.baseStructOf(typeDecl: TypeDecl<GlobalTypeId>): TypeDecl.Struct<GlobalTypeId>? = when (typeDecl) {
    is TypeDecl.Ref -> getStruct(typeDecl.id)

    is TypeDecl.XRef -> byXRef(typeDecl)?.body as? TypeDecl.Struct<GlobalTypeId>

    is TypeDecl.InlineDef -> getStruct(typeDecl.id)
        ?: (typeDecl.inner as? TypeDecl.Struct)
        ?: baseStructOf(typeDecl.inner)

    else -> null
}

/**
 * Collects a class's full vtable slot list from its inheritance chain and orders it by the
 * stab-declared slot offset. The walk gathers virtuals bases-first so a derived override (matched
 * by name) replaces the inherited slot and its offset wins; output order is set by the final sort,
 * not the walk. Override matching is by name only — fine for the non-overloaded gcc 3.4.4 corpus.
 */
fun HarvestIndex.collectAllVirtuals(struct: TypeDecl.Struct<GlobalTypeId>) = object {
    val table: MutableList<Method<GlobalTypeId>> = mutableListOf()
    private val visited: MutableSet<TypeDecl.Struct<GlobalTypeId>> = mutableSetOf()

    private fun walkBases(cls: TypeDecl.Struct<GlobalTypeId>) {
        for (base in cls.bases) {
            baseStructOf(base.type)?.takeIf { visited.add(it) }?.let { collectAll(it) }
        }
    }

    fun collectAll(cls: TypeDecl.Struct<GlobalTypeId>) {
        walkBases(cls)
        for (m in cls.methods.filter { it.virt == VirtKind.VIRTUAL }) {
            val idx = table.indexOfFirst { it.name == m.name }
            if (idx >= 0) table[idx] = m else table += m
        }
    }
}.run {
    collectAll(struct)
    table.sortedBy { it.vtableOffsetBits!! }
}
