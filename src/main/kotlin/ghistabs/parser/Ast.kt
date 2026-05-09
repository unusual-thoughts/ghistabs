package ghistabs.parser

/** Identifies a type within a CU: (file-number, type-number). */
data class TypeId(
    val cu: Int,
    val n: Int,
)

enum class Access { PRIVATE, PROTECTED, PUBLIC }

enum class VirtKind { NORMAL, STATIC, VIRTUAL, PURE_VIRTUAL }

enum class AggrKind { STRUCT, UNION, CLASS }

/** Type AST. Sealed; every grammar form has a constructor here. */
sealed interface TypeDecl {
    /** Forward reference to a type defined elsewhere by id. */
    data class Ref(
        val id: TypeId,
    ) : TypeDecl

    /** Sun range descriptor: `r<id>;<min>;<max>;` — encodes integer/char widths. */
    data class Range(
        val of: TypeId,
        val min: Long,
        val max: Long,
    ) : TypeDecl

    data class Pointer(
        val pointee: TypeDecl,
    ) : TypeDecl

    data class Reference(
        val referent: TypeDecl,
    ) : TypeDecl

    data class Const(
        val inner: TypeDecl,
    ) : TypeDecl

    data class Volatile(
        val inner: TypeDecl,
    ) : TypeDecl

    data class Array(
        val element: TypeDecl,
        val length: Long?,
        val indexType: TypeDecl?,
    ) : TypeDecl

    data class Enum(
        val members: List<Pair<String, Long>>,
    ) : TypeDecl

    data class Struct(
        val kind: AggrKind,
        val sizeBytes: Long,
        val bases: List<BaseDecl>,
        val fields: List<FieldDecl>,
        val methods: List<MethodDecl>,
        val hasVTablePointerMarker: Boolean,
        val vtableTargetTypeId: TypeId?,
    ) : TypeDecl

    data class FunctionT(
        val ret: TypeDecl,
        val params: List<TypeDecl>,
    ) : TypeDecl

    /** Pointer-to-member-function (the `#` descriptor body). */
    data class Method(
        val cls: TypeDecl,
        val ret: TypeDecl,
        val params: List<TypeDecl>,
    ) : TypeDecl

    /** GCC complex/floating: `R<n>;<size>;0;`. n encodes 3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout. */
    data class Complex(
        val rCode: Int,
        val sizeBytes: Int,
    ) : TypeDecl

    /** Cross-reference: `xs<name>:` / `xu<name>:` / `xc<name>:` — incomplete tag. */
    data class XRef(
        val kind: AggrKind,
        val tagName: String,
    ) : TypeDecl

    /** Wrapper carrying an `@s<n>;` size attribute around an inner type. */
    data class WithSizeAttr(
        val sizeBits: Int,
        val inner: TypeDecl,
    ) : TypeDecl

    /** Builtin form `(0,N)` resolved by id only — content provided by BuiltinTable in Phase 3. */
    data object Builtin : TypeDecl
}

data class FieldDecl(
    val name: String,
    val type: TypeDecl,
    val offsetBits: Long,
    val sizeBits: Long,
    val isStatic: Boolean,
)

data class BaseDecl(
    val type: TypeDecl,
    val isVirtual: Boolean,
    val access: Access,
    val offsetBits: Long,
)

data class MethodDecl(
    val name: String,
    val mangled: String?,
    val signature: TypeDecl,
    val access: Access,
    val virt: VirtKind,
    val isConst: Boolean,
    val isVolatile: Boolean,
    /** Vtable offset in bits when `virt == VIRTUAL`, else null. */
    val vtableOffsetBits: Long?,
)

/** Symbol AST: what one stab record's `name:descriptor` decodes to. */
sealed interface SymbolDecl {
    val name: String

    /** `:F` / `:f`. Top-level function (file-static if `f`). */
    data class Function(
        override val name: String,
        val isFileStatic: Boolean,
        val signature: TypeDecl,
    ) : SymbolDecl

    /** `:p` */
    data class StackParam(
        override val name: String,
        val type: TypeDecl,
    ) : SymbolDecl

    /** `:P` (register param) or `:R` (alt). */
    data class RegParam(
        override val name: String,
        val type: TypeDecl,
        val regNum: Int,
    ) : SymbolDecl

    /** `:r` register variable. */
    data class RegLocal(
        override val name: String,
        val type: TypeDecl,
        val regNum: Int,
    ) : SymbolDecl

    /** Plain stack local (a `:` descriptor with no class letter, or `:V` static-local). */
    data class StackLocal(
        override val name: String,
        val type: TypeDecl,
    ) : SymbolDecl

    /** `:T` tagged type (struct/union/class/enum tag). */
    data class TaggedType(
        override val name: String,
        val id: TypeId,
        val body: TypeDecl,
    ) : SymbolDecl

    /** `:t` typedef. */
    data class Typedef(
        override val name: String,
        val id: TypeId,
        val body: TypeDecl,
    ) : SymbolDecl

    /** `:G` */
    data class Global(
        override val name: String,
        val type: TypeDecl,
    ) : SymbolDecl

    /** `:S` file-static / `:V` static-local. */
    data class StaticVar(
        override val name: String,
        val type: TypeDecl,
        val isFunctionLocal: Boolean,
    ) : SymbolDecl
}

class StabsParseException(
    val pos: Int,
    val src: String,
    msg: String,
) : RuntimeException("at $pos in '${src.take(120)}': $msg") {
    /** Returns a one-line excerpt with a `^` caret at `pos`. */
    fun excerpt(): String {
        val start = (pos - 30).coerceAtLeast(0)
        val end = (pos + 30).coerceAtMost(src.length)
        val window = src.substring(start, end)
        val caret = " ".repeat(pos - start) + "^"
        return "$window\n$caret"
    }
}
