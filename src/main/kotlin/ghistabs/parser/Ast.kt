package ghistabs.parser

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonClassDiscriminator

/** Identifies a type within a CU: (file-number, type-number). */
@Serializable(with = LocalTypeIdAsStringSerializer::class)
data class LocalTypeId(val file: Int, val n: Int) {
    override fun toString() = "($file,$n)"
}

@Serializable
data class GlobalTypeId(val source: SourceFile, val n: Int)

@Serializable
sealed class SourceFile : Comparable<SourceFile> {
    abstract val filename: String
    abstract val cu: String

    override fun compareTo(other: SourceFile): Int = filename.compareTo(other.filename)

    @Serializable
    data class HeaderSource(val header: HeaderFile) : SourceFile() {
        override val filename get() = header.filename
        override val cu get() = header.originatingCu
    }

    @Serializable
    data class CUSource(override val cu: String) : SourceFile() {
        override val filename get() = cu
    }
}

class LocalTypeIdAsStringSerializer : KSerializer<LocalTypeId> {
    override val descriptor = PrimitiveSerialDescriptor(
        this::class.java.canonicalName,
        PrimitiveKind.STRING,
    )

    override fun serialize(encoder: Encoder, value: LocalTypeId) {
        encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): LocalTypeId {
        TODO("Not yet implemented")
    }
}

enum class Access { PRIVATE, PROTECTED, PUBLIC }

enum class VirtKind { NORMAL, STATIC, VIRTUAL, PURE_VIRTUAL }

enum class AggrKind { STRUCT, UNION, CLASS }

/** Type AST. Sealed; every grammar form has a constructor here. */
@Serializable
sealed interface TypeDecl {
    /** Forward reference to a type defined elsewhere by id. */
    @Serializable
    data class Ref(val id: LocalTypeId) : TypeDecl

    /** Sun range descriptor: `r<id>;<min>;<max>;` — encodes integer/char widths. */
    @Serializable
    data class Range(val of: LocalTypeId, val min: Long, val max: Long) : TypeDecl

    @Serializable
    data class Pointer(val pointee: TypeDecl) : TypeDecl

    @Serializable
    data class Reference(val referent: TypeDecl) : TypeDecl

    @Serializable
    data class Const(val inner: TypeDecl) : TypeDecl

    @Serializable
    data class Volatile(val inner: TypeDecl) : TypeDecl

    @Serializable
    data class Array(val element: TypeDecl, val length: Long?, val indexType: TypeDecl?) : TypeDecl

    @Serializable
    data class Enum(val members: List<Pair<String, Long>>) : TypeDecl

    @Serializable
    data class Struct(
        val kind: AggrKind,
        val sizeBytes: Long,
        val bases: List<BaseDecl>,
        val fields: List<FieldDecl>,
        val methods: List<MethodDecl>,
        val hasVTablePointerMarker: Boolean,
        val vtableTargetTypeId: LocalTypeId?,
    ) : TypeDecl

    @Serializable
    data class FunctionT(val ret: TypeDecl, val params: List<TypeDecl>) : TypeDecl

    /** Pointer-to-member-function (the `#` descriptor body). */
    @Serializable
    data class Method(val cls: TypeDecl, val ret: TypeDecl, val params: List<TypeDecl>) : TypeDecl

    /** GCC complex/floating: `R<n>;<size>;0;`. n encodes 3=cfloat, 4=cdouble, 5=cldouble per gcc/dbxout. */
    @Serializable
    data class Complex(val rCode: Int, val sizeBytes: Int) : TypeDecl

    /** Cross-reference: `xs<name>:` / `xu<name>:` / `xc<name>:` — incomplete tag. */
    @Serializable
    data class XRef(val kind: AggrKind, val tagName: String) : TypeDecl

    /** Wrapper carrying an `@s<n>;` size attribute around an inner type. */
    @Serializable
    data class WithSizeAttr(val sizeBits: Int, val inner: TypeDecl) : TypeDecl

    /** Inline type definition: `(cu,n)=<body>` where the binding `(cu,n)` is preserved for Phase 3. */
    @Serializable
    data class InlineDef(val id: LocalTypeId, val body: TypeDecl) : TypeDecl
}

@Serializable
data class FieldDecl(
    val name: String,
    val type: TypeDecl,
    val offsetBits: Long,
    val sizeBits: Long,
    val isStatic: Boolean,
)

@Serializable
data class BaseDecl(val type: TypeDecl, val isVirtual: Boolean, val access: Access, val offsetBits: Long)

@Serializable
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
@Serializable
@OptIn(ExperimentalSerializationApi::class)
@JsonClassDiscriminator("kind")
sealed interface SymbolDecl {
    val name: String

    /** `:F` / `:f`. Top-level function (file-static if `f`). */
    @Serializable
    data class Function(override val name: String, val isFileStatic: Boolean, val signature: TypeDecl) : SymbolDecl

    /** `:p` */
    @Serializable
    data class StackParam(override val name: String, val type: TypeDecl) : SymbolDecl

    /** `:P` (register param) or `:R` (alt). */
    @Serializable
    data class RegParam(override val name: String, val type: TypeDecl, val regNum: Int) : SymbolDecl

    /** `:r` register variable. */
    @Serializable
    data class RegLocal(override val name: String, val type: TypeDecl, val regNum: Int) : SymbolDecl

    /** Plain stack local (a `:` descriptor with no class letter, or `:V` static-local). */
    @Serializable
    data class StackLocal(override val name: String, val type: TypeDecl) : SymbolDecl

    /** `:T` tagged type (struct/union/class/enum tag). */
    @Serializable
    data class TaggedType(override val name: String, val id: LocalTypeId, val body: TypeDecl) : SymbolDecl

    /** `:t` typedef. */
    @Serializable
    data class Typedef(override val name: String, val id: LocalTypeId, val body: TypeDecl) : SymbolDecl

    /** `:G` */
    @Serializable
    data class Global(override val name: String, val type: TypeDecl) : SymbolDecl

    /** `:S` file-static / `:V` static-local. */
    @Serializable
    data class StaticVar(override val name: String, val type: TypeDecl, val isFunctionLocal: Boolean) : SymbolDecl
}

class StabsParseException(val pos: Int, val src: String, msg: String) :
    RuntimeException("at $pos in '${src.take(120)}': $msg") {
    /** Returns a one-line excerpt with a `^` caret at `pos`. */
    fun excerpt(): String {
        val start = (pos - 30).coerceAtLeast(0)
        val end = (pos + 30).coerceAtMost(src.length)
        val window = src.substring(start, end)
        val caret = " ".repeat(pos - start) + "^"
        return "$window\n$caret"
    }
}
