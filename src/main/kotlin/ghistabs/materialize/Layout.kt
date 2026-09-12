package ghistabs.materialize

import ghistabs.index.TypeGraph
import ghistabs.materialize.abi.Itanium
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Aggregate.Base
import ghistabs.parse.TypeDecl.Aggregate.Method

/** Pure C++ record-layout decisions: where the vfptr goes and how base subobjects are spliced in. */
object Layout {

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
 * `DECL_VINDEX`. Counted from wherever the `{vfptr}` points, so the keys are address-point-based
 * under Itanium (`_ZTVSt9type_info` in `crypto_mi_test_gcc421_fullstabs` declares 0, 1 and 5 — its
 * dtor, deleting dtor and `__is_function_p` exactly) but record-start-based under gcc 2.x, where the
 * reserved entries are numbered too. [ghistabs.materialize.abi.CxxAbi.reservedEntries] is that difference;
 * rebasing by it is the caller's job, since only the vtable symbol states which ABI spelled the record.
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
