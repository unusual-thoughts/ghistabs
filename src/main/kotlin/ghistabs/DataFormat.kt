package ghistabs

import ghidra.app.util.PseudoData
import ghidra.docking.settings.Settings
import ghidra.program.model.address.Address
import ghidra.program.model.data.Array
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemBuffer
import ghidra.program.model.scalar.Scalar
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual
import ghidra.program.model.data.Enum as GhidraEnum

/**
 * A `@Serializable` class read out of a [Data] laid as a [Composite], so a structure in memory comes
 * back as a value instead of a run of `getScalar(name)` lookups. Its properties are the composite's
 * fields by name, a nested class reads the nested composite, a list reads an array's (or any
 * composite's) components in order. A primitive reads the field's [Scalar], a char also a `Character`
 * and a boolean also a `Boolean`; an enum takes the name a Ghidra enum gives the value, else the
 * value as its ordinal. An [Address] or the field's own [Data] reads as a [SerialAddress] or [SerialData].
 *
 * A field the composite lacks falls back to the property's default, then to null; one it has but the
 * class doesn't name is ignored.
 */
@OptIn(ExperimentalSerializationApi::class)
object DataFormat {
    val serializersModule = SerializersModule {
        contextual(AddressSerializer)
        contextual(DataSerializer)
    }

    fun <T> decode(deserializer: DeserializationStrategy<T>, from: Data): T =
        Reader(from).decodeSerializableValue(deserializer)

    inline fun <reified T> decode(from: Data): T = decode(serializersModule.serializer<T>(), from)

    /** A pointer field as the address it holds. */
    object AddressSerializer : KSerializer<Address> {
        override val descriptor = PrimitiveSerialDescriptor("ghidra.Address", PrimitiveKind.LONG)
        override fun deserialize(decoder: Decoder) =
            reader(decoder).element.value as? Address ?: throw reader(decoder).mismatch("an address")
        override fun serialize(encoder: Encoder, value: Address) = decodeOnly()
    }

    /** A field as its [Data], left for the caller to read on. */
    object DataSerializer : KSerializer<Data> {
        override val descriptor = PrimitiveSerialDescriptor("ghidra.Data", PrimitiveKind.STRING)
        override fun deserialize(decoder: Decoder) = reader(decoder).element
        override fun serialize(encoder: Encoder, value: Data) = decodeOnly()
    }

    private fun decodeOnly(): Nothing = throw SerializationException("DataFormat only decodes")

    private fun reader(decoder: Decoder) =
        decoder as? Reader ?: throw SerializationException("${decoder::class.simpleName} is no DataFormat decoder")

    /** Reads the composite [data]; before its structure begins, [data] is the value itself. */
    // A decodeX per primitive is the decoder's contract, not a class doing too much.
    @Suppress("TooManyFunctions")
    private class Reader(private val data: Data) : AbstractDecoder() {
        override val serializersModule = DataFormat.serializersModule
        private var index = -1
        private var name = data.fieldName ?: data.dataType.name
        private var current: Data? = data
        private val byName by lazy {
            (0 until data.numComponents).mapNotNull(data::getComponent).associateBy { it.fieldName }
        }

        val element get() = current ?: throw SerializationException("No '$name' in ${data.dataType.name}")

        fun mismatch(wanted: String) =
            SerializationException("'$name' in ${data.dataType.name} holds ${element.value}, not $wanted")

        override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
            val list = descriptor.kind == StructureKind.LIST
            while (++index < if (list) data.numComponents else descriptor.elementsCount) {
                name = if (list) "[$index]" else descriptor.getElementName(index)
                current = if (list) data.getComponent(index) else byName[name]
                if (current == null && !list && descriptor.isElementOptional(index)) continue
                return index
            }
            return CompositeDecoder.DECODE_DONE
        }

        override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
            if (descriptor.kind == StructureKind.MAP) throw SerializationException("A composite holds no map")
            return Reader(element)
        }

        override fun decodeNotNullMark() =
            current?.let { it.baseDataType.let { t -> t is Composite || t is Array } || it.value != null } == true

        override fun decodeNull(): Nothing? = null

        private fun long() = when (val v = element.value) {
            is Scalar -> v.value
            is Char -> v.code.toLong()
            is Boolean -> if (v) 1 else 0
            is Address -> v.offset
            else -> throw mismatch("an integer")
        }

        private fun double() = (element.value as? Number)?.toDouble() ?: throw mismatch("a float")

        override fun decodeBoolean() = element.value as? Boolean ?: (long() != 0L)
        override fun decodeByte() = long().toByte()
        override fun decodeShort() = long().toShort()
        override fun decodeInt() = long().toInt()
        override fun decodeLong() = long()
        override fun decodeFloat() = double().toFloat()
        override fun decodeDouble() = double()
        override fun decodeChar() = element.value as? Char ?: long().toInt().toChar()
        override fun decodeString() = element.value as? String ?: throw mismatch("a string")

        override fun decodeEnum(enumDescriptor: SerialDescriptor): Int {
            val value = long()
            val index = (element.baseDataType as? GhidraEnum)?.getName(value)
                ?.let(enumDescriptor::getElementIndex) ?: value.toInt()
            return index.takeIf { it in 0..<enumDescriptor.elementsCount }
                ?: throw SerializationException("No ${enumDescriptor.serialName} for $value in '$name'")
        }
    }
}

/** A pointer field's [Address], as a property type the serialization plugin accepts. */
typealias SerialAddress =
    @Serializable(with = DataFormat.AddressSerializer::class)
    Address

/** A field's own [Data], as a property type the serialization plugin accepts. */
typealias SerialData =
    @Serializable(with = DataFormat.DataSerializer::class)
    Data

/**
 * A structure whose data's [Data.getValue] is its layout decoded as a [T] through [DataFormat], so
 * `program.readAt(addr, it)?.value` or [Program.readAs] hands back the class. That holds for pseudo data
 * and for a field of another such structure; laid in a listing, it resolves to a plain structure,
 * whose data [decode] still reads.
 */
class SerialStructure<T : Any>(
    name: String,
    private val deserializer: DeserializationStrategy<T>,
    private val valueClass: Class<T>,
    dtm: DataTypeManager? = null,
) : StructureDataType(name, 0, dtm) {
    override fun getValue(buf: MemBuffer, settings: Settings?, length: Int): T =
        DataFormat.decode(deserializer, buf as? Data ?: PseudoData(buf.memory.program, buf.address, this, buf))

    override fun getValueClass(settings: Settings?) = valueClass

    // Ghidra clones a structure into each manager or composite that takes it, which would drop the decoder.
    override fun clone(dtm: DataTypeManager?) = if (dtm == dataTypeManager) this else copy(dtm)

    override fun copy(dtm: DataTypeManager?) = SerialStructure(name, deserializer, valueClass, dtm).also {
        it.description = description
        it.replaceWith(this)
    }

    companion object {
        /** A [SerialStructure] for [T], laid out by [layout]. */
        inline operator fun <reified T : Any> invoke(
            name: String,
            dtm: DataTypeManager? = null,
            layout: StructureDataType.() -> Unit,
        ) = SerialStructure(name, DataFormat.serializersModule.serializer<T>(), T::class.java, dtm).apply(layout)
    }
}

/** This composite as a [T]; see [DataFormat]. */
inline fun <reified T> Data.decode(): T = DataFormat.decode(this)

/** [dt] laid at [addr] as a [T], or null if it can't be read there. */
inline fun <reified T> Program.read(addr: Address, dt: DataType): T? = readAt(addr, dt)?.decode()
