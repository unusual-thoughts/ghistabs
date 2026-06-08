@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parser

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
 * Represents one BINCL-or-source-file entity. Two CUs that include or EXCL the same
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
