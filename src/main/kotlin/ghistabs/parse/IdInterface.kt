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

/** BINCL-or-source-file entity. CUs that BINCL/EXCL the same (filename, checksum) share one instance. */
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

    /** CU source. [directory] is set from the leading directory-`N_SO` (one ending in `/`). */
    @Serializable(with = ToStringSerializer::class)
    data class CUSource(override val filename: String, val directory: String? = null) : SourceFile() {
        override fun toString() = if (directory != null) "$directory$filename" else filename
    }
}

class ToStringSerializer<T> : KSerializer<T> {
    override val descriptor = PrimitiveSerialDescriptor("ToString", PrimitiveKind.STRING)
    override fun serialize(encoder: Encoder, value: T) = encoder.encodeString(value.toString())
    override fun deserialize(decoder: Decoder) =
        throw UnsupportedOperationException("ToStringSerializer is serialize-only")
}

interface Globalizer {
    fun globalIdFor(id: LocalTypeId): GlobalTypeId
}

/**
 * Replace every [LocalTypeId] in this tree with a [GlobalTypeId] via [g].
 * Hoisting of inline definitions into the top-level `typeAsts` collection is done by the
 * sibling walker (`walkDefinitions` / `appendAsts`), not here.
 */
@Suppress("UNCHECKED_CAST")
fun TypeDecl<LocalTypeId>.globalize(g: Globalizer): TypeDecl<GlobalTypeId> = when (this) {
    is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.Enum, is TypeDecl.XRef, is TypeDecl.Builtin ->
        this as TypeDecl<GlobalTypeId>

    is TypeDecl.Range -> TypeDecl.Range(g.globalIdFor(of), min, max)

    // Negative-id Refs never reach here — parser emits [TypeDecl.Builtin] for those.
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
        rawKind,
        sizeBytes,
        bases.map { BaseDecl(it.type.globalize(g), it.isVirtual, it.access, it.offsetBits) },
        fields.map { FieldDecl(it.name, it.type.globalize(g), it.offsetBits, it.sizeBits, it.isStatic, it.access) },
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
