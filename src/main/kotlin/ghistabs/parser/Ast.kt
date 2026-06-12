@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parser

import kotlinx.serialization.Contextual
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonClassDiscriminator

enum class Access { PRIVATE, PROTECTED, PUBLIC }

enum class VirtKind { NORMAL, STATIC, VIRTUAL, PURE_VIRTUAL }

enum class AggrKind { STRUCT, UNION, CLASS, ENUM }

/** Type AST. Sealed; every grammar form has a constructor here. */
@Serializable
sealed interface TypeDecl<out Id : IdInterface> {
    /** Forward reference to a type defined elsewhere by id. */
    @Serializable
    data class Ref<Id : IdInterface>(@Contextual val id: Id) : TypeDecl<Id>

    /** Sun range descriptor: `r<id>;<min>;<max>;` — encodes integer/char widths. */
    @Serializable
    data class Range<Id : IdInterface>(@Contextual val of: Id, val min: Long, val max: Long) : TypeDecl<Id>

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
        val kind: AggrKind,
        val sizeBytes: Long,
        val bases: List<BaseDecl<Id>>,
        val fields: List<FieldDecl<Id>>,
        val methods: List<MethodDecl<Id>>,
        val hasVTablePointerMarker: Boolean,
        @Contextual val vtableTargetTypeId: Id?,
    ) : TypeDecl<Id>

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
     * gcc/XCOFF builtin-type slot — `Ref` to a negative type number (`(0,-N)`).
     * Per the stabs spec these refer to compiler-table builtins (`-1`=int,
     * `-2`=char, `-16`=`bool`, …) and have no defining stab. The same slot
     * means the same primitive across every CU, so [contentHash] keys on
     * [slot] alone — keeping it as a per-CU [Ref] would let `bool` in CU
     * A differ from `bool` in CU B, breaking content-equivalence dedup.
     */
    @Serializable
    data class Builtin<Id : IdInterface>(val slot: Int) : TypeDecl<Id>

    /** Inline type definition: `(cu,n)=<body>` where the binding `(cu,n)` is preserved for Phase 3. */
    @Serializable
    data class InlineDef<Id : IdInterface>(@Contextual val id: Id, val body: TypeDecl<Id>) : TypeDecl<Id>
}

@Serializable
data class IdWithHash(val id: GlobalTypeId, val hash: Int?)

class WithHashSerializer(val hashes: Map<GlobalTypeId, Int>) : KSerializer<GlobalTypeId> {
    override val descriptor = PrimitiveSerialDescriptor("WithHash", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: GlobalTypeId) = encoder.encodeSerializableValue(
        IdWithHash.serializer(),
        IdWithHash(value, hashes[value]),
    )

    override fun deserialize(decoder: Decoder) = throw UnsupportedOperationException("serialize-only")
}

@Serializable
data class FieldDecl<Id : IdInterface>(
    val name: String,
    val type: TypeDecl<Id>,
    val offsetBits: Long,
    val sizeBits: Long,
    val isStatic: Boolean,
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

    /** Plain stack local (a `:` descriptor with no class letter, or `:V` static-local). */
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
