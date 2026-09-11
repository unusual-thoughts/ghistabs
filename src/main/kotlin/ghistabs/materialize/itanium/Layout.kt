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

/**
 * Byte offset of the vptr [typeDecl] declares, or null if it declares none. The single answer to
 * "where does this class say its vptr is": the Itanium ABI puts it at 0, gcc 2.x appends it after
 * the class's own fields, and only the stab says which.
 */
fun vptrOffsetBytesOf(typeDecl: TypeDecl.Aggregate<GlobalTypeId>): Int? = typeDecl.fields
    .firstOrNull { isVptrFieldName(it.name) }
    ?.let { (it.offsetBits / 8).toInt() }

/** Does [typeDecl] inherit a vfptr from a polymorphic base subobject (vs. introducing its own)? */
fun TypeGraph.hasPolymorphicBaseSubobject(typeDecl: TypeDecl.Aggregate<GlobalTypeId>) =
    firstPolymorphicBase(typeDecl) != null

/**
 * Lowest-offset polymorphic base, or null. Determines whether to insert a vfptr or inherit.
 *
 * A declared `_vptr$X` field counts, and has to: under plain `-gstabs` gcc emits no member functions
 * at all, so `xmltest_gcc421`'s `TiXmlVisitor:T(0,436)=s4_vptr$TiXmlVisitor:(0,166),0,32;;` is the
 * *only* evidence its bases are polymorphic. Without it every derived class looked non-polymorphic,
 * so nothing ever asked where its vfptr should come from.
 */
fun TypeGraph.firstPolymorphicBase(typeDecl: TypeDecl.Aggregate<GlobalTypeId>): Base<GlobalTypeId>? = typeDecl.bases
    .sortedBy { it.offsetBits }
    .firstOrNull { base ->
        resolveStruct(base.type)?.run {
            hasVTablePointerMarker ||
                methods.any { it.virt == VirtKind.VIRTUAL } ||
                fields.any { isVptrFieldName(it.name) } ||
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
 * How deep [typeDecl] sits in its inheritance graph, so a caller can process bases before the
 * classes that embed them. [VfptrModel.SPLIT_BASE] needs that order: it derives a base's
 * `<Base>_fields` from the base's *materialized* layout, which is only vptr-less once the base has
 * had its own vfptr placed. Cycles can't arise from well-formed stabs but [seen] makes that true
 * regardless of what the binary declares.
 */
fun TypeGraph.inheritanceDepth(
    typeDecl: TypeDecl.Aggregate<GlobalTypeId>,
    seen: MutableSet<TypeDecl.Aggregate<GlobalTypeId>> = mutableSetOf(),
): Int = if (!seen.add(typeDecl)) {
    0
} else {
    1 + (typeDecl.bases.mapNotNull { resolveStruct(it.type) }.maxOfOrNull { inheritanceDepth(it, seen) } ?: -1)
}

/**
 * A class's virtuals from its whole inheritance chain, keyed by the slot index gcc declares — the
 * `*<n>` a method's stab carries after its cv-qualifier, which `dbxout.c` emits straight from
 * `DECL_VINDEX`. Measured against `_ZTVSt9type_info` in `crypto_mi_test_gcc421_fullstabs`, whose
 * stabs declare 0, 1 and 5: those are the record's dtor, deleting dtor and `__is_function_p` slots
 * exactly, counted from the address point with no bias for the header words.
 *
 * The index is the slot's identity, which settles both overriding (a derived method reuses its
 * base's index, so the bases-first walk lets the override win) and overloading (two same-named
 * virtuals hold different ones) without matching on names.
 *
 * Sparse by nature, hence a map and not a list: a class only declares the slots its own CU saw, and
 * libstdc++/libsupc++ link without stabs, so an inherited half of the table simply isn't here. The
 * holes are real slots and the caller fills them from the record in memory.
 */
fun TypeGraph.collectAllVirtuals(struct: TypeDecl.Aggregate<GlobalTypeId>): Map<Int, Method<GlobalTypeId>> = buildMap {
    val visited = mutableSetOf<TypeDecl.Aggregate<GlobalTypeId>>()
    fun walk(cls: TypeDecl.Aggregate<GlobalTypeId>) {
        for (base in cls.bases) resolveStruct(base.type)?.takeIf(visited::add)?.let(::walk)
        cls.methods
            .filter { it.virt == VirtKind.VIRTUAL }
            .forEach { m -> m.vtableOffsetBits?.let { put(it.toInt(), m) } }
    }
    walk(struct)
}

/**
 * Where a polymorphic class's `{vfptr}` comes from, which decides whether a virtual call resolves to
 * a named slot or overruns into `vfptr[N]`.
 *
 * The vptr physically sits at offset 0 *inside* the primary base subobject, so a derived class can
 * only carry a pointer to its **own** vftable if something gives way — and it has to, because the
 * static type of the field is what the decompiler indexes. With one shared field typed
 * `<Root>_vftable *`, every derived slot lands past the end of the root's table: `xmltest_gcc421`
 * renders 31 of its 40 virtual calls as `vfptr[4].~TiXmlBase` and never mentions a derived vftable
 * type at all.
 *
 * An enum rather than a flag because there is an obvious third way: Ghidra's own
 * `RecoveredClassHelper` expands the base subobject away entirely and puts `vftablePtr` at offset 0,
 * trading the `_base_` component for the pointer.
 */
enum class VfptrModel {
    /** One `{vfptr}` on the root of each hierarchy, inherited through `_base_`. Derived slots overrun. */
    INHERITED,

    /**
     * Each polymorphic class owns a `{vfptr}` typed to its own vftable, and embeds its primary base
     * as that base's fields *without* the vptr — one extra struct per polymorphic class, shared by
     * every class that derives from it. Keeps the `_base_` subobject component that
     * [ghistabs.materialize.Layout] models inheritance with.
     */
    SPLIT_BASE,
}
