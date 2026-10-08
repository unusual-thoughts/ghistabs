@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
@file:UseSerializers(BigIntegerSerializer::class)

package ghistabs.parse

import kotlinx.serialization.*
import kotlinx.serialization.json.JsonClassDiscriminator
import java.math.BigInteger

enum class Access { PRIVATE, PROTECTED, PUBLIC }

/** Method kind from the stabs method-block trailer: `.` normal, `?` static, `*` virtual. */
enum class VirtKind { NORMAL, STATIC, VIRTUAL }

/** What a [SymbolDecl.NamedType] binds: `:T` a tag (struct/union/class/enum), `:t` a typedef alias. */
enum class TypeNameKind { TAG, TYPEDEF }

/**
 * The three record kinds stabs can name, as body descriptors (`s`/`u`/`e`) and as forward-reference
 * kinds (`xs`/`xu`/`xe`). There is deliberately no CLASS: gcc spells every class `s`, and the Sun
 * manual's forward-reference grammar (p125) glosses `s` as "class/structure" outright — so class-ness
 * is never read, only guessed, by [TypeDecl.Aggregate.isCxxClass].
 */
enum class AggrKind { STRUCT, UNION, ENUM, }

@Serializable
enum class StaticScope {
    GLOBAL,
    FILE,
    FUNCTION,
    ;

    fun comment() = when (this) {
        GLOBAL -> "global"
        FILE -> "file static"
        FUNCTION -> "function static"
    }

    /** The storage class the declaration spells: `S` and `V` have internal linkage, only `G` is extern. */
    fun storageClass() = if (this == GLOBAL) "" else "static "
}

@Serializable
enum class FunctionScope {
    GLOBAL,
    FILE,
    ;

    /** The storage class the definition spells: `f` has internal linkage, `F` is extern. */
    fun storageClass() = if (this == FILE) "static " else ""
}

@Serializable
enum class VariableLocation {
    REGISTER,
    STACK,
}

/** Type AST. Sealed; every grammar form has a constructor here. */
@Serializable
sealed interface TypeDecl<out Id : IdInterface> {
    /**
     * Width in bits as stated or implied by the stab itself, or null when the stab doesn't
     * determine it — [Pointer]/[Reference] (program address size) and unresolved [Ref]/[XRef].
     * Never guesses a target ABI; callers that need a concrete size for those must ask the
     * program's data organization. gcc's `@s<n>;` attribute, the one width a stab states outright
     * rather than implying, is the `sizeAttr` of the only nodes it precedes: [Range], [Builtin], [Enum].
     */
    val sizeBits: Long? get() = null

    /** [sizeBits] in whole bytes. */
    val sizeBytes: Long? get() = sizeBits?.let { (it + 7) / 8 }

    /**
     * The one type a single-layer node wraps: [Pointer], [Reference], [Const], [Volatile] and [InlineDef].
     * Nothing reads it but the default [children], which it spares those five an override of.
     */
    val wrapped: TypeDecl<Id>? get() = null

    /** The id this node binds directly: the one a [Ref] points at, or the one an [InlineDef] defines. */
    val id: Id? get() = null

    /**
     * Every TypeDecl nested directly in this one, one list per slot (an [Array]'s element and index type, an
     * [Aggregate]'s bases, fields, methods and vptr base), each in declaration order. The generic walks over
     * a type read only this, so a nested type left out is one they never see:
     * - `TypeStore.hoistInlineDefs` registers each [InlineDef] it reaches, and one it misses leaves its id
     *   undefined;
     * - `ContentIndex` keys a type by [layoutData] and these, slot by slot, unless it has a key of its own (a
     *   Ghidra primitive, an [Aggregate]);
     * - `TypeLocations` and `FileRenderer`'s include claims follow it to the ids a type names.
     */
    val children: List<List<TypeDecl<Id>>> get() = wrapped?.let { listOf(listOf(it)) } ?: emptyList()

    /**
     * What tells two nodes of one class apart besides their [children], for `ContentIndex`'s content key:
     * bounds, sizes, names, enum members. It must hold only what is the same in every CU that declares the
     * type, never a [GlobalTypeId], whose source differs per CU.
     */
    val layoutData: List<Any> get() = emptyList<Nothing>()

    /** Forward reference to a type defined elsewhere by id. */
    @Serializable
    data class Ref<Id : IdInterface>(@Contextual override val id: Id) : TypeDecl<Id>

    /**
     * gcc's void: a type *explicitly* defined as itself (`(x,y)=(x,y)`). Only the `=`-definition
     * form is void — a bare `name:t(x,y)` (no `=`) is a [Ref] forward reference, resolved elsewhere.
     * Materializes to Ghidra's VoidDataType.
     */
    @Serializable
    data object Void : TypeDecl<Nothing> {
        override val sizeBits = 0L
    }

    /**
     * Sun range descriptor: `r<id>;<min>;<max>;` — encodes integer/char widths. [inner] is the base type, a
     * child: a [Ref], usually to the range itself, or the [InlineDef] gcc writes for an array index's
     * sizetype, `r(0,54)=r(0,54);0;037777777777;;0;1;`, which is the only definition of that id.
     */
    @Serializable
    data class Range<Id : IdInterface>(
        val inner: TypeDecl<Id>,
        val lower: BigInteger,
        val upper: BigInteger,
        val sizeAttr: Long? = null,
    ) : TypeDecl<Id> {
        /**
         * The bounds as the low 64 bits every consumer wants — gcc means the wrap (`unsigned long
         * long`'s max *is* -1L to it), and the exact value stays in [lower]/[upper] for the one
         * question the wrap can't answer: how wide the type is.
         */
        val min get() = lower.toLong()
        val max get() = upper.toLong()

        /**
         * A literal `0;-1`: unsigned, with a max the emitter didn't state
         * - gcc means 64 bits and says so by having [inner] point to itself
         * - Sun's C compiler writes the same for 32-bit `unsigned int`/`unsigned long` against `int`
         * - gcc 2.6.3 writes it for `unsigned int` while spelling `long long unsigned int` out as 2^64-1.
         */
        val boundsUnfit get() = lower == BigInteger.ZERO && upper == BigInteger.valueOf(-1)

        override val sizeBits = sizeAttr ?: when {
            // Must resolve [inner] with [DataTypeRegistry.resolveBuiltin] to know the upper bound
            boundsUnfit -> null

            lower == BigInteger.ZERO && upper == BigInteger.ZERO -> 0L

            // Unsigned: the lower bound spans the type.
            lower == BigInteger.ZERO -> widthHolding(upper.bitLength())

            // Signed: the upper bound spans the type, plus its sign bit.
            lower.signum() < 0 -> widthHolding(lower.bitLength() + 1)

            // A true subrange (`1;10`) states an interval, not a width; gcc gives it an int.
            else -> 4L
        }?.times(8)

        override val children get() = listOf(listOf(inner))

        // The exact bounds, not [min]/[max]: narrowed to a Long, gcc 2.6.3's `unsigned int` and `long long
        // unsigned int` are both (0, -1) and would hash as one type. Only a range with no Ghidra primitive
        // (an odd stated width, `@s24;`) is keyed by these at all; a self-based [inner] adds just a back-edge.
        override val layoutData get() = listOfNotNull(lower, upper, sizeAttr)

        private companion object {
            /**
             * Smallest integer width holding [bits]. A bound fixes the width only from below — gcc
             * 3.4.5 writes `__int128`'s max as 2^95-1 — and integer widths are powers of two bytes,
             * so round up to one.
             */
            fun widthHolding(bits: Int) = ((bits + 7) / 8).coerceAtLeast(1)
                .let { if (it.takeHighestOneBit() == it) it else it.takeHighestOneBit() * 2 }
                .toLong()
        }
    }

    /**
     * GCC float encoding `r<base>;<NBYTES>;0;`. `<base>` is decorative (per stabs spec / gdb
     * `read_range_type`) — hashing by size only keeps cross-CU floats content-equivalent.
     */
    @Serializable
    data class Float<Id : IdInterface>(override val sizeBytes: Long) : TypeDecl<Id> {
        override val sizeBits get() = sizeBytes * 8
        override val layoutData get() = listOf(sizeBytes)
    }

    // Both are address-sized, which the stab never states — leave sizeBits null
    @Serializable
    data class Pointer<Id : IdInterface>(val inner: TypeDecl<Id>) : TypeDecl<Id> {
        override val wrapped get() = inner
    }

    /** C++ reference */
    @Serializable
    data class Reference<Id : IdInterface>(val inner: TypeDecl<Id>) : TypeDecl<Id> {
        override val wrapped get() = inner
    }

    @Serializable
    data class Const<Id : IdInterface>(val inner: TypeDecl<Id>) : TypeDecl<Id> {
        override val wrapped get() = inner
        override val sizeBits get() = inner.sizeBits
    }

    @Serializable
    data class Volatile<Id : IdInterface>(val inner: TypeDecl<Id>) : TypeDecl<Id> {
        override val wrapped get() = inner
        override val sizeBits get() = inner.sizeBits
    }

    @Serializable
    data class Array<Id : IdInterface>(val element: TypeDecl<Id>, val length: Long?, val indexType: TypeDecl<Id>?) :
        TypeDecl<Id> {
        /** gcc usually leaves [length] null and puts the bound in [indexType] (`ar<idx>;lo;hi`). */
        val declaredElements: Long?
            get() = length ?: (indexType as? Range)?.let { it.max - it.min + 1 }?.takeIf { it > 0 }

        override val children get() = listOf(listOf(element), listOfNotNull(indexType))
        override val layoutData get() = listOfNotNull(length)
        override val sizeBits get() = element.sizeBits?.let { elementSize -> length?.let { it * elementSize } }
    }

    @Serializable
    data class Enum<Id : IdInterface>(val members: List<Pair<String, Long>>, val sizeAttr: Long? = null) :
        TypeDecl<Id> {
        // sizeof(int), as gdb's read_enum_type has it, unless gcc states `@s<n>` (`-fshort-enums`)
        override val sizeBits = sizeAttr ?: 32L
        override val layoutData get() = listOfNotNull(members, sizeAttr)
    }

    @Serializable
    data class Aggregate<Id : IdInterface>(
        val kind: AggrKind,
        override val sizeBytes: Long,
        val bases: List<Base<Id>>,
        val fields: List<Field<Id>>,
        val methods: List<Method<Id>>,
        // Trailing `~%<type>;` section: the vptr-owning base (gdb's VPTR_BASETYPE), a full read_type —
        // usually a `Ref`, but an inline forward-xref (`(cu,n)=xsName:`) for RTTI/exception classes.
        // Non-null iff the class is polymorphic; supersedes the separate boolean marker gcc used to emit.
        val vptrBasetype: TypeDecl<Id>?,
    ) : TypeDecl<Id> {
        val hasVTablePointerMarker get() = vptrBasetype != null

        /** Whether the record carries a body at all — a bare `s0` / `u0` is a declaration. */
        val hasMembers get() = fields.isNotEmpty() || methods.isNotEmpty()

        /** Members only a C++ record can have: a method block, or a vfptr under either spelling. */
        private val hasCxxMembers get() = methods.isNotEmpty() ||
            hasVTablePointerMarker ||
            fields.any { isVptrFieldName(it.name) }

        /** Whether the class says it has a vptr of its own: a vtable marker, a virtual method, or a vptr field. */
        val declaresVptr get() = hasVTablePointerMarker ||
            methods.any { it.virt == VirtKind.VIRTUAL } ||
            fields.any { isVptrFieldName(it.name) }

        /**
         * C++ at all, so worth class materialization. Inheritance qualifies whatever its access —
         * gcc emits the `!N,` base block only for C++ records, a C struct never has one.
         */
        val hasCxxSurface get() = hasCxxMembers || bases.isNotEmpty()

        /**
         * Was the keyword `class`? Unrecoverable in principle — dbxout.c emits the `/N` visibility
         * marker only for non-public or non-FIELD_DECL members, so a public member is spelled
         * identically under either keyword — leaving only these tells. Narrower than [hasCxxSurface]
         * at exactly one term: a *non-public* base is evidence, because the default base access is
         * private for `class` and public for `struct`, while `struct D : public B` is idiomatic C++
         * and evidence of nothing.
         */
        val isCxxClass get() = hasCxxMembers || bases.any { it.access != Access.PUBLIC }

        override val children get() = listOf(
            bases.map { it.type },
            fields.map { it.type },
            methods.map { it.signature },
            listOfNotNull(vptrBasetype),
        )

        override val sizeBits get() = sizeBytes * 8
        override val layoutData get() = listOf(kind, sizeBytes)

        @Serializable
        data class Field<Id : IdInterface>(
            val name: String,
            val type: TypeDecl<Id>,
            val offsetBits: Long,
            val sizeBits: Long,
            val isStatic: Boolean,
            val access: Access,
            /**
             * Linkage name of a static data member (`alnum:/2(5,44):_ZNSt10ctype_base5alnumE;`). It is the
             * only link stabs give between the member and its emitted symbol — none of these carry their own
             * `G`/`S` address stab — so it is what lets a global be typed from its member declaration rather
             * than left to the demangler. Null for ordinary members.
             *
             * No default: a `globalize`-shaped rebuild that forgets it would silently drop the link.
             */
            val mangled: String?,
        )

        @Serializable
        data class Base<Id : IdInterface>(
            val type: TypeDecl<Id>,
            val isVirtual: Boolean,
            val access: Access,
            val offsetBits: Long,
        )

        @Serializable
        data class Method<Id : IdInterface>(
            val name: String,
            /** The stab's physname field, or null when it states none: gcc 2.x leaves this blank far
             *  more often than it fills it (98 of tinyxml's 274 method entries), and "" is not a
             *  symbol, so the parser folds blank to null. Not always a complete mangled name either:
             *  gcc 2.x sometimes fills it with only the mangled argument list. */
            val mangled: String?,
            val signature: TypeDecl<Id>,
            val access: Access,
            val virt: VirtKind,
            val isConst: Boolean,
            val isVolatile: Boolean,
            /** Vtable offset in bits when `virt == VIRTUAL`, else null. */
            val vtableOffsetBits: Long?,
        ) {
            /** `virtual `/`static ` — Ghidra's prototypeString models neither, so the stab is the only source. */
            val declPrefix get() = when (virt) {
                VirtKind.VIRTUAL -> "virtual "
                VirtKind.STATIC -> "static "
                VirtKind.NORMAL -> ""
            }

            /** Trailing cv-qualifiers, which in C++ sit after the parameter list: `int at(size_t) const;`. */
            val declSuffix get() = buildString {
                if (isConst) append(" const")
                if (isVolatile) append(" volatile")
            }
        }
    }

    @Serializable
    data class FreeFunction<Id : IdInterface>(val ret: TypeDecl<Id>, val params: List<TypeDecl<Id>>) : TypeDecl<Id> {
        override val children get() = listOf(listOf(ret) + params)
    }

    /** Pointer-to-member-function (the `#` descriptor body). */
    @Serializable
    data class Method<Id : IdInterface>(
        /** Null for gdb's *stub* method (`##<ret>;`), which states no domain — see `Parser.parseMethod`. */
        val cls: TypeDecl<Id>?,
        val ret: TypeDecl<Id>,
        val params: List<TypeDecl<Id>>,
    ) : TypeDecl<Id> {
        override val children get() = listOf(listOfNotNull(cls) + ret, params)
    }

    /**
     * Member type `@<class>,<type>` — gcc's OFFSET_TYPE, the data-member counterpart of [Method]'s `#`.
     * It makes `int A::*`, a byte offset into [cls] rather than an address: gcc ≤ 3.3 wraps it in a
     * [Pointer] (`*@A,int`), ≥ 3.4 emits it bare.
     */
    @Serializable
    data class Member<Id : IdInterface>(val cls: TypeDecl<Id>, val inner: TypeDecl<Id>) : TypeDecl<Id> {
        override val children get() = listOf(listOf(cls, inner))
    }

    /** GCC complex/floating: `R<n>;<size>;0;`. n encodes 3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout. */
    @Serializable
    data class Complex<Id : IdInterface>(val rCode: Int, override val sizeBytes: Long) : TypeDecl<Id> {
        override val sizeBits get() = sizeBytes * 8
        override val layoutData get() = listOf(rCode, sizeBytes)
    }

    /** Cross-reference: `xs<name>:` / `xu<name>:` / `xc<name>:` — incomplete tag. */
    @Serializable
    data class XRef<Id : IdInterface>(val kind: AggrKind, val tagName: String) : TypeDecl<Id> {
        override val layoutData get() = listOf(kind, tagName)
    }

    /**
     * gcc/XCOFF builtin slot (`(0,-N)`). No defining stab — same slot means same primitive
     * in every CU (`-1`=int, `-2`=char, `-16`=bool, …). Only the legacy `@s<n>;-<slot>` form states a
     * width, in [sizeAttr]; bool's is the recurring one.
     */
    @Serializable
    data class Builtin<Id : IdInterface>(val slot: Int, val sizeAttr: Long? = null) : TypeDecl<Id> {
        override val sizeBits get() = sizeAttr
        override val layoutData get() = listOfNotNull(slot, sizeAttr)
    }

    /** Inline type definition: `(cu,n)=<body>` where the binding `(cu,n)` is preserved for Phase 3. */
    @Serializable
    data class InlineDef<Id : IdInterface>(@Contextual override val id: Id, val inner: TypeDecl<Id>) : TypeDecl<Id> {
        override val wrapped get() = inner
    }

    /**
     * The body kinds an `xs`/`xu`/`xe` cross-reference is able to name: the definition is here, rather
     * than the body pointing at one elsewhere. A capability of the kind — not a claim that anything
     * actually references this one.
     *
     * Independent of how the name was bound, in both directions (measured over the corpus): 18,803 `:t`
     * typedefs carry an Aggregate or Enum body — enums are mostly typedef-bound — while 126 `:T` tags
     * carry a self-`Ref`, a forward declaration with no definition to resolve to. So neither implies
     * the other, and an index of what an xref can reach has to ask this rather than [TypeNameKind].
     */
    val canBeXRefTarget get() = this is Aggregate || this is Enum

    /** Bodies that materialize their own named DataType (own their ghidraName), as opposed to
     *  wrappers/refs/aliases whose byId entry points at another type's dt. Only these are classified. */
    val ownsMaterializedType get() = canBeXRefTarget || this is FreeFunction || this is Method

    val isComplete get() = when (this) {
        is Aggregate -> sizeBytes > 0
        is Enum -> members.isNotEmpty()
        else -> false
    }

    fun matchesXRefKind(xref: AggrKind) = when (this) {
        is Aggregate -> kind == xref
        is Enum -> xref == AggrKind.ENUM
        else -> false
    }
}

typealias LocalTypeDecl = TypeDecl<LocalTypeId>
typealias GlobalTypeDecl = TypeDecl<GlobalTypeId>

/** Symbol AST: what one stab record's `name:descriptor` decodes to. */
@Serializable
@OptIn(ExperimentalSerializationApi::class)
@JsonClassDiscriminator("kind")
sealed interface SymbolDecl<Id : IdInterface> {
    val name: String
    val type: TypeDecl<Id>

    /** `:F` / `:f`. Top-level function (file-static if `f`). */
    @Serializable
    data class Function<Id : IdInterface>(
        override val name: String,
        val scope: FunctionScope,
        /**  the return type */
        override val type: TypeDecl<Id>,
    ) : SymbolDecl<Id>

    /**
     *  `:p` stack param
     *  `:P` (register param) or `:R` (alt)
     *  */
    @Serializable
    data class Param<Id : IdInterface>(
        override val name: String,
        override val type: TypeDecl<Id>,
        val location: VariableLocation,
    ) : SymbolDecl<Id>

    /**
     *  `:r` register variable.
     *  stack variable `:` descriptor with no class letter (gdb's `l`/`s`, i.e. the type  number follows immediately).
     */
    @Serializable
    data class Local<Id : IdInterface>(
        override val name: String,
        override val type: TypeDecl<Id>,
        val location: VariableLocation,
    ) : SymbolDecl<Id>

    /**
     * `:T` tag or `:t` typedef — a name bound to a type id. The two are one form: gcc emits `Tt`
     * for `typedef struct foo {} foo`, and everything downstream treats them alike (both register
     * a [ghistabs.harvest.Type] at [id]). [kind] keeps the source spelling for rendering.
     */
    @Serializable
    data class NamedType<Id : IdInterface>(
        override val name: String,
        @SerialName("tagOrTypedef") val kind: TypeNameKind,
        @Contextual val id: Id,
        override val type: TypeDecl<Id>,
    ) : SymbolDecl<Id>

    /** `:S` file-static / `:V` function-static / `:G` global */
    @Serializable
    data class Static<Id : IdInterface>(
        override val name: String,
        override val type: TypeDecl<Id>,
        val scope: StaticScope,
    ) : SymbolDecl<Id>

    /**
     * `:c=` addressless compile-time constant. Integral forms (`i`/`e`/`b`/`c`) carry the
     * value; `e` also carries an explicit type, the others a synthesized builtin int.
     * Non-integral forms (`r`/`s`/`S`) are consumed but not represented (value 0) — g++/x86
     * never emits them.
     */
    @Serializable
    data class Constant<Id : IdInterface>(
        override val name: String,
        override val type: TypeDecl<Id>,
        val value: Long,
    ) : SymbolDecl<Id>
}
