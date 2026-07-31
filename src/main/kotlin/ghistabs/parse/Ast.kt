@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parse

import kotlinx.serialization.Contextual
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

enum class Access { PRIVATE, PROTECTED, PUBLIC }

/** Method kind from the stabs method-block trailer: `.` normal, `?` static, `*` virtual. */
enum class VirtKind { NORMAL, STATIC, VIRTUAL }

enum class AggrKind {
    STRUCT,
    UNION,
    CLASS,
    ENUM,
    ;

    /**
     * Best-effort C++-style declaration from the stab function name.
     * Ghidra's `DemangledFunction.signature` prepends Ghidra's guess at
     * the calling convention (often the wrong `__rustcall` for Itanium
     * `_ZN…` symbols because the unified demangler can't distinguish
     * gcc-Itanium from legacy-Rust at the entry point). Strip any
     * leading `__*call ` token and rebuild from the demangler's name +
     * params instead.
     */
    fun cxxKeyword() = when (this) {
        STRUCT -> "struct"
        UNION -> "union"
        CLASS -> "class"
        ENUM -> "enum"
    }
}

/** Type AST. Sealed; every grammar form has a constructor here. */
@Serializable
sealed interface TypeDecl<out Id : IdInterface> {
    /** Forward reference to a type defined elsewhere by id. */
    @Serializable
    data class Ref<Id : IdInterface>(@Contextual val id: Id) : TypeDecl<Id>

    /**
     * gcc's void: a type *explicitly* defined as itself (`(x,y)=(x,y)`). Only the `=`-definition
     * form is void — a bare `name:t(x,y)` (no `=`) is a [Ref] forward reference, resolved elsewhere.
     * Materializes to Ghidra's VoidDataType.
     */
    @Serializable
    data object Void : TypeDecl<Nothing>

    /** Sun range descriptor: `r<id>;<min>;<max>;` — encodes integer/char widths. */
    @Serializable
    data class Range<Id : IdInterface>(@Contextual val of: Id, val min: Long, val max: Long) : TypeDecl<Id>

    /**
     * GCC float encoding `r<base>;<NBYTES>;0;`. `<base>` is decorative (per stabs spec / gdb
     * `read_range_type`) — hashing by size only keeps cross-CU floats content-equivalent.
     */
    @Serializable
    data class Float<Id : IdInterface>(val sizeBytes: Int) : TypeDecl<Id>

    @Serializable
    data class Pointer<Id : IdInterface>(val pointee: TypeDecl<Id>) : TypeDecl<Id>

    /** C++ reference */
    @Serializable
    data class Reference<Id : IdInterface>(val referent: TypeDecl<Id>) : TypeDecl<Id>

    @Serializable
    data class Const<Id : IdInterface>(val inner: TypeDecl<Id>) : TypeDecl<Id>

    @Serializable
    data class Volatile<Id : IdInterface>(val inner: TypeDecl<Id>) : TypeDecl<Id>

    @Serializable
    data class Array<Id : IdInterface>(val element: TypeDecl<Id>, val length: Long?, val indexType: TypeDecl<Id>?) :
        TypeDecl<Id>

    @Serializable
    data class Enum<Id : IdInterface>(val members: List<Pair<String, Long>>) : TypeDecl<Id>

    @Serializable
    data class Struct<Id : IdInterface>(
        val rawKind: AggrKind,
        val sizeBytes: Long,
        val bases: List<BaseDecl<Id>>,
        val fields: List<FieldDecl<Id>>,
        val methods: List<MethodDecl<Id>>,
        // Trailing `~%<type>;` section: the vptr-owning base (gdb's VPTR_BASETYPE), a full read_type —
        // usually a `Ref`, but an inline forward-xref (`(cu,n)=xsName:`) for RTTI/exception classes.
        // Non-null iff the class is polymorphic; supersedes the separate boolean marker gcc used to emit.
        val vptrBasetype: TypeDecl<Id>? = null,
    ) : TypeDecl<Id> {
        val hasVTablePointerMarker get() = vptrBasetype != null

        // gcc 3.x stabs emit `s` for both `struct` and `class`; promote to "class" when
        // any method or base carries non-public access, OR when there are any methods
        // at all (plain C structs have none — the presence of methods means C++).
        val kind
            get() = when (rawKind) {
                AggrKind.STRUCT if (methods.isNotEmpty() || bases.any { it.access != Access.PUBLIC }) -> AggrKind.CLASS
                else -> rawKind
            }
    }

    @Serializable
    data class FunctionT<Id : IdInterface>(val ret: TypeDecl<Id>, val params: List<TypeDecl<Id>>) : TypeDecl<Id>

    /** Pointer-to-member-function (the `#` descriptor body). */
    @Serializable
    data class Method<Id : IdInterface>(val cls: TypeDecl<Id>, val ret: TypeDecl<Id>, val params: List<TypeDecl<Id>>) :
        TypeDecl<Id>

    /** GCC complex/floating: `R<n>;<size>;0;`. n encodes 3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout. */
    @Serializable
    data class Complex<Id : IdInterface>(val rCode: Int, val sizeBytes: Int) : TypeDecl<Id>

    /** Cross-reference: `xs<name>:` / `xu<name>:` / `xc<name>:` — incomplete tag. */
    @Serializable
    data class XRef<Id : IdInterface>(val kind: AggrKind, val tagName: String) : TypeDecl<Id>

    /** Wrapper carrying an `@s<n>;` size attribute around an inner type. */
    @Serializable
    data class WithSizeAttr<Id : IdInterface>(val sizeBits: Int, val inner: TypeDecl<Id>) : TypeDecl<Id>

    /**
     * gcc/XCOFF builtin slot (`(0,-N)`). No defining stab — same slot means same primitive
     * in every CU (`-1`=int, `-2`=char, `-16`=bool, …). Hashed by [slot] alone.
     */
    @Serializable
    data class Builtin<Id : IdInterface>(val slot: Int) : TypeDecl<Id>

    /** Inline type definition: `(cu,n)=<body>` where the binding `(cu,n)` is preserved for Phase 3. */
    @Serializable
    data class InlineDef<Id : IdInterface>(@Contextual val id: Id, val body: TypeDecl<Id>) : TypeDecl<Id>
}

val TypeDecl<*>.isXRefTarget get() = this is TypeDecl.Struct || this is TypeDecl.Enum

/** Bodies that materialize their own named DataType (own their ghidraName), as opposed to
 *  wrappers/refs/aliases whose byId entry points at another type's dt. Only these are classified. */
val TypeDecl<*>.ownsMaterializedType get() = isXRefTarget || this is TypeDecl.FunctionT || this is TypeDecl.Method

val TypeDecl<*>.isComplete
    get() = when (this) {
        is TypeDecl.Struct -> sizeBytes > 0
        is TypeDecl.Enum -> members.isNotEmpty()
        else -> false
    }

fun TypeDecl<*>.matchesXRefKind(xref: AggrKind) = when (this) {
    is TypeDecl.Struct -> rawKind == xref
    is TypeDecl.Enum -> xref == AggrKind.ENUM
    else -> false
}

val TypeDecl<*>.sizeBytes
    get() = when (this) {
        is TypeDecl.Struct -> sizeBytes

        is TypeDecl.Enum -> 4L

        // gcc default
        else -> 0L
    }

@Serializable
data class FieldDecl<Id : IdInterface>(
    val name: String,
    val type: TypeDecl<Id>,
    val offsetBits: Long,
    val sizeBits: Long,
    val isStatic: Boolean,
    val access: Access,
)

@Serializable
data class BaseDecl<Id : IdInterface>(
    val type: TypeDecl<Id>,
    val isVirtual: Boolean,
    val access: Access,
    val offsetBits: Long,
)

@Serializable
data class MethodDecl<Id : IdInterface>(
    val name: String,
    val mangled: String?,
    val signature: TypeDecl<Id>,
    val access: Access,
    val virt: VirtKind,
    val isConst: Boolean,
    val isVolatile: Boolean,
    /** Vtable offset in bits when `virt == VIRTUAL`, else null. */
    val vtableOffsetBits: Long?,
)

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
        val isFileStatic: Boolean,
        override val type: TypeDecl<Id>,
    ) : SymbolDecl<Id>

    /** `:p` */
    @Serializable
    data class StackParam<Id : IdInterface>(override val name: String, override val type: TypeDecl<Id>) : SymbolDecl<Id>

    /** `:P` (register param) or `:R` (alt). */
    @Serializable
    data class RegParam<Id : IdInterface>(override val name: String, override val type: TypeDecl<Id>, val regNum: Int) :
        SymbolDecl<Id>

    /** `:r` register variable. */
    @Serializable
    data class RegLocal<Id : IdInterface>(override val name: String, override val type: TypeDecl<Id>, val regNum: Int) :
        SymbolDecl<Id>

    /** Plain stack local — a `:` descriptor with no class letter (gdb's `l`/`s`, i.e. the type
     *  number follows immediately). `:V` is a procedure-scope static and maps to [StaticVar]. */
    @Serializable
    data class StackLocal<Id : IdInterface>(override val name: String, override val type: TypeDecl<Id>) : SymbolDecl<Id>

    /** `:T` tagged type (struct/union/class/enum tag). */
    @Serializable
    data class TaggedType<Id : IdInterface>(
        override val name: String,
        @Contextual val id: Id,
        override val type: TypeDecl<Id>,
    ) : SymbolDecl<Id>

    /** `:t` typedef. */
    @Serializable
    data class Typedef<Id : IdInterface>(
        override val name: String,
        @Contextual val id: Id,
        override val type: TypeDecl<Id>,
    ) : SymbolDecl<Id>

    /** `:G` */
    @Serializable
    data class Global<Id : IdInterface>(override val name: String, override val type: TypeDecl<Id>) : SymbolDecl<Id>

    /** `:S` file-static / `:V` static-local. */
    @Serializable
    data class StaticVar<Id : IdInterface>(
        override val name: String,
        override val type: TypeDecl<Id>,
        val isFunctionLocal: Boolean,
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

class StabsParseException(val pos: Int, val src: String, msg: String) :
    RuntimeException("at $pos in '$src': $msg") {
    /** Returns a one-line excerpt with a `^` caret at `pos`. */
    fun excerpt(): String {
        val start = (pos - 30).coerceAtLeast(0)
        val end = (pos + 30).coerceAtMost(src.length)
        val window = src.substring(start, end)
        val caret = " ".repeat(pos - start) + "^"
        return "$window\n$caret"
    }
}
