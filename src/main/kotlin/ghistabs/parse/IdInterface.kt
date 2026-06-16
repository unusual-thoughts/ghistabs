@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parse

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = ToStringSerializer::class)
sealed interface IdInterface {
    val n: Int
}

/** Identifies a type within a CU: (file-number, type-number). */
@Serializable(with = ToStringSerializer::class)
data class LocalTypeId(val file: Int, override val n: Int) : IdInterface {
    override fun toString() = "($file,$n)"
}

@Serializable(with = ToStringSerializer::class)
data class GlobalTypeId(val source: SourceFile, override val n: Int) : IdInterface {
    override fun toString() = "[$source,$n]"
}

/**
 * Represents one BINCL-or-source-file entity. Two CUs this include or EXCL the same
 * (filename, checksum) share a single HeaderFile instance.
 */
@Serializable(with = ToStringSerializer::class)
data class HeaderFile(val filename: String, val checksum: Long, val originatingCu: SourceFile.CUSource?) {
    override fun toString(): String = "$filename#$checksum#$originatingCu"
}

@Serializable(with = ToStringSerializer::class)
sealed class SourceFile : Comparable<SourceFile> {
    abstract val filename: String

    override fun compareTo(other: SourceFile): Int = filename.compareTo(other.filename)

    @Serializable(with = ToStringSerializer::class)
    data class HeaderSource(val header: HeaderFile) : SourceFile() {
        override val filename get() = header.filename
        override fun toString() = header.toString()
    }

    @Serializable(with = ToStringSerializer::class)
    data class CUSource(override val filename: String) : SourceFile() {
        override fun toString() = filename
    }
}

object ToStringSerializer : KSerializer<Any> {
    override val descriptor = PrimitiveSerialDescriptor("ToString", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: Any) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder) =
        throw UnsupportedOperationException("ToStringSerializer is serialize-only")
}

interface Globalizer {
    fun globalIdFor(id: LocalTypeId): GlobalTypeId
}

/**
 * Recursively converts a [TypeDecl] (with [LocalTypeId] nodes) to [TypeDecl] (with [GlobalTypeId] nodes)
 * by replacing local type references with global ones.
 *
 * Identity on terminal nodes: leaf types like [TypeDecl.Builtin] and [TypeDecl.Void] pass
 * through unchanged via `@Suppress("UNCHECKED_CAST")`.
 *
 * Recursion contract: every [TypeDecl] variant is handled; none falls through unprocessed.
 * For recursive types, child nodes are recursively globalized.
 *
 * InlineDef side effect: when an [TypeDecl.InlineDef] is encountered, its body is
 * globalized AND a [TypeAst] is emitted as a side effect (the side effect itself
 * happens in sibling methods [walkDefinitions] and [appendAsts], not within [globalize]).
 * This ensures inline-type definitions are hoisted into the top-level [typeAsts] collection.
 */
@Suppress("UNCHECKED_CAST")
fun TypeDecl<LocalTypeId>.globalize(g: Globalizer): TypeDecl<GlobalTypeId> = when (this) {
    is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.XRef, is TypeDecl.Builtin ->
        this as TypeDecl<GlobalTypeId>

    is TypeDecl.Range -> TypeDecl.Range(g.globalIdFor(of), min, max)

    // Refs with negative ids never reach this point — the parser
    // (see [Parser.parseType]) emits [TypeDecl.Builtin] for those.
    is TypeDecl.Ref -> TypeDecl.Ref(g.globalIdFor(id))

    is TypeDecl.Const -> TypeDecl.Const(inner.globalize(g))

    is TypeDecl.Volatile -> TypeDecl.Volatile(inner.globalize(g))

    is TypeDecl.WithSizeAttr -> TypeDecl.WithSizeAttr(sizeBits, inner.globalize(g))

    is TypeDecl.Pointer -> TypeDecl.Pointer(pointee.globalize(g))

    is TypeDecl.Reference -> TypeDecl.Reference(referent.globalize(g))

    is TypeDecl.Array -> TypeDecl.Array(element.globalize(g), length, indexType?.globalize(g))

    is TypeDecl.FunctionT -> TypeDecl.FunctionT(ret.globalize(g), params.map { it.globalize(g) })

    is TypeDecl.Method -> TypeDecl.Method(
        cls.globalize(g),
        ret.globalize(g),
        this.params.map { it.globalize(g) },
    )

    is TypeDecl.Struct -> TypeDecl.Struct(
        kind,
        sizeBytes,
        bases.map { BaseDecl(it.type.globalize(g), it.isVirtual, it.access, it.offsetBits) },
        fields.map { FieldDecl(it.name, it.type.globalize(g), it.offsetBits, it.sizeBits, it.isStatic) },
        methods.map {
            MethodDecl(
                it.name,
                it.mangled,
                it.signature.globalize(g),
                it.access,
                it.virt,
                it.isConst,
                it.isVolatile,
                it.vtableOffsetBits,
            )
        },
        hasVTablePointerMarker,
        vtableTargetTypeId?.let { g.globalIdFor(it) },
    )

    is TypeDecl.InlineDef -> TypeDecl.InlineDef(g.globalIdFor(id), body.globalize(g))
}

fun SymbolDecl<LocalTypeId>.globalize(g: Globalizer) = when (this) {
    is SymbolDecl.Function -> SymbolDecl.Function(name, isFileStatic, type.globalize(g))
    is SymbolDecl.Global -> SymbolDecl.Global(name, type.globalize(g))
    is SymbolDecl.RegLocal -> SymbolDecl.RegLocal(name, type.globalize(g), regNum)
    is SymbolDecl.RegParam -> SymbolDecl.RegLocal(name, type.globalize(g), regNum)
    is SymbolDecl.StackLocal -> SymbolDecl.StackLocal(name, type.globalize(g))
    is SymbolDecl.StackParam -> SymbolDecl.StackParam(name, type.globalize(g))
    is SymbolDecl.StaticVar -> SymbolDecl.StaticVar(name, type.globalize(g), isFunctionLocal)
    is SymbolDecl.TaggedType -> SymbolDecl.TaggedType(name, g.globalIdFor(id), type.globalize(g))
    is SymbolDecl.Typedef -> SymbolDecl.Typedef(name, g.globalIdFor(id), type.globalize(g))
}
