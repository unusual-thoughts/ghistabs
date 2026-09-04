package ghistabs.materialize.itanium

import ghistabs.index.TypeGraph
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeDecl.Aggregate.Base
import ghistabs.parse.TypeDecl.Aggregate.Method
import ghistabs.parse.VirtKind
import ghistabs.parse.isVptrFieldName

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

        return if (componentAtTargetOffset.fieldName?.let(::isVptrFieldName) == true) {
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
fun TypeGraph.hasPolymorphicBaseSubobject(typeDecl: TypeDecl.Aggregate<GlobalTypeId>) =
    firstPolymorphicBase(typeDecl) != null

/** Lowest-offset polymorphic base, or null. Determines whether to insert a vfptr or inherit. */
fun TypeGraph.firstPolymorphicBase(typeDecl: TypeDecl.Aggregate<GlobalTypeId>): Base<GlobalTypeId>? = typeDecl.bases
    .sortedBy { it.offsetBits }
    .firstOrNull { base ->
        resolveStruct(base.type)?.run {
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
fun TypeGraph.virtualBases(typeDecl: TypeDecl.Aggregate<GlobalTypeId>) = buildList {
    val seen = mutableSetOf<TypeDecl.Aggregate<GlobalTypeId>>()
    fun walk(cls: TypeDecl.Aggregate<GlobalTypeId>) {
        if (!seen.add(cls)) return
        for (base in cls.bases) {
            if (base.isVirtual) add(base)
            resolveStruct(base.type)?.let(::walk)
        }
    }
    walk(typeDecl)
}

fun TypeGraph.resolveStruct(typeDecl: GlobalTypeDecl) = resolve<TypeDecl.Aggregate<GlobalTypeId>>(typeDecl)

/**
 * Collects a class's full vtable slot list from its inheritance chain and orders it by the
 * stab-declared slot offset. The walk gathers virtuals bases-first so a derived override (matched
 * by name) replaces the inherited slot and its offset wins; output order is set by the final sort,
 * not the walk. Override matching is by name only — fine for the non-overloaded gcc 3.4.4 corpus.
 */
fun TypeGraph.collectAllVirtuals(struct: TypeDecl.Aggregate<GlobalTypeId>) = object {
    val table: MutableList<Method<GlobalTypeId>> = mutableListOf()
    private val visited: MutableSet<TypeDecl.Aggregate<GlobalTypeId>> = mutableSetOf()

    private fun walkBases(cls: TypeDecl.Aggregate<GlobalTypeId>) {
        for (base in cls.bases) {
            resolveStruct(base.type)?.takeIf { visited.add(it) }?.let { collectAll(it) }
        }
    }

    fun collectAll(cls: TypeDecl.Aggregate<GlobalTypeId>) {
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
