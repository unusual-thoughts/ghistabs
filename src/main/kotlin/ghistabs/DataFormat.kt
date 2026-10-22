package ghistabs

import ghidra.docking.settings.Settings
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.data.Array
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
import java.lang.reflect.ParameterizedType
import java.lang.reflect.Type
import java.nio.ByteBuffer
import java.nio.charset.Charset
import kotlin.reflect.javaType
import kotlin.reflect.typeOf
import ghidra.program.model.data.Enum as GhidraEnum

/**
 * A `@Serializable` class read out of a [Data] laid as a [Composite], so a structure in memory comes
 * back as a value instead of a run of `getScalar(name)` lookups. Its properties are the composite's
 * fields by name, a nested class reads the nested composite, a list reads an array's (or any
 * composite's) components in order. A primitive reads the field's [Scalar], a char also a `Character`
 * and a boolean also a `Boolean`; an enum takes the name a Ghidra enum gives the value, else the
 * value as its ordinal. An [Address] or the field's own [Data] reads as a [SerialAddress] or [SerialData].
 *
 * A char pointer field reads as a string: the NUL-terminated UTF-8, UTF-16 or UTF-32 it points at, by the
 * char's width, or the charset [Text] names, found within [MAX_STRING_BYTES] or [Text.maxBytes]. A null
 * pointer, no terminator in reach, or bytes the charset can't decode read as null.
 * Any other typed pointer field reads as a [Ptr] to dereference later, or, marked [Deref], as what it points at.
 *
 * A field the composite lacks falls back to the property's default, then to null; one it has but the
 * class doesn't name is ignored.
 */
@OptIn(ExperimentalSerializationApi::class)
object DataFormat {
    /** How far past a char pointer a string's terminator is looked for. */
    const val MAX_STRING_BYTES = 0x1000

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

    internal fun <T> pointer(decoder: Decoder, target: DeserializationStrategy<T>): Ptr<T> {
        val field = reader(decoder).element
        val to = field.value as? Address ?: throw reader(decoder).mismatch("an address")
        val text = target.descriptor.kind == PrimitiveKind.STRING && field.charWidth != null
        val spec = reader(decoder).spec
        return Ptr(to) {
            val pointee = if (text) field.takeIf { it.pointedString(spec) != null } else field.deref()
            pointee?.let { Reader(it, spec).decodeSerializableValue(target) }
        }
    }

    internal fun decodeOnly(): Nothing = throw SerializationException("DataFormat only decodes")

    private fun reader(decoder: Decoder) =
        decoder as? Reader ?: throw SerializationException("${decoder::class.simpleName} is no DataFormat decoder")

    /** Reads the composite [data]; before its structure begins, [data] is the value itself. */
    // A decodeX per primitive is the decoder's contract, not a class doing too much.
    @Suppress("TooManyFunctions")
    private class Reader(private val data: Data, var spec: Text? = null) : AbstractDecoder() {
        override val serializersModule = DataFormat.serializersModule
        private var index = -1
        private var name = data.fieldName ?: data.dataType.name
        private var current: Data? = data
        private var text = false
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
                if (!list) spec = descriptor.getElementAnnotations(index).filterIsInstance<Text>().singleOrNull()
                text = descriptor.getElementDescriptor(index).kind == PrimitiveKind.STRING && current?.charWidth != null
                val deref = !list && !text && descriptor.getElementAnnotations(index).any { it is Deref }
                if (deref) current = current?.deref()
                if (current == null && !list && descriptor.isElementOptional(index)) continue
                return index
            }
            return CompositeDecoder.DECODE_DONE
        }

        override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
            if (descriptor.kind == StructureKind.MAP) throw SerializationException("A composite holds no map")
            return Reader(element, spec)
        }

        override fun decodeNotNullMark() =
            current?.let { if (text) it.pointedString(spec) != null else it.isAggregate || it.value != null } == true

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
        override fun decodeString() =
            element.value as? String ?: element.pointedString(spec) ?: throw mismatch("a string")

        override fun decodeEnum(enumDescriptor: SerialDescriptor): Int {
            val value = long()
            val index = (element.baseDataType as? GhidraEnum)?.getName(value)
                ?.let(enumDescriptor::getElementIndex) ?: value.toInt()
            return index.takeIf { it in 0..<enumDescriptor.elementsCount }
                ?: throw SerializationException("No ${enumDescriptor.serialName} for $value in '$name'")
        }
    }
}

/** The non-null address the pointer [this] holds. */
private val Data.target get() = (value as? Address)?.takeIf { it.offset != 0L }

/** What the pointer [this] holds points at, laid as its pointee type ([Program.dataAt]); null for a null pointer. */
private fun Data.deref(): Data? {
    val pointee = (baseDataType as? Pointer)?.dataType
        ?: throw SerializationException("'$fieldName' is no typed pointer, so has nothing to dereference")
    return target?.let { program.dataAt(it, pointee) }
}

/** The width of the char [this] points at, if it is a char pointer. */
private val Data.charWidth: Int? get() {
    val pointee = (baseDataType as? Pointer)?.dataType
    return when (val char = (pointee as? TypeDef)?.baseDataType ?: pointee) {
        is CharDataType -> 1
        is WideCharDataType, is WideChar16DataType, is WideChar32DataType -> char.length
        else -> null
    }
}

private val Data.isAggregate get() = baseDataType.let { it is Composite || it is Array }

/** The NUL-terminated string the char pointer [this] points at, read as [spec] says; see [DataFormat]. */
private fun Data.pointedString(spec: Text?): String? {
    val width = charWidth ?: return null
    val to = target ?: return null
    val limit = spec?.maxBytes ?: DataFormat.MAX_STRING_BYTES
    val bytes = program.bytesAt(to).cBytesHere(0..<limit, width) ?: return null
    val big = program.memory.isBigEndian
    val charset = spec?.charset?.takeIf { it.isNotEmpty() }?.let(Charset::forName) ?: when (width) {
        1 -> Charsets.UTF_8
        2 -> if (big) Charsets.UTF_16BE else Charsets.UTF_16LE
        else -> if (big) Charsets.UTF_32BE else Charsets.UTF_32LE
    }
    return runCatching { charset.newDecoder().decode(ByteBuffer.wrap(bytes)).toString() }.getOrNull()
}

/**
 * How a char pointer field's string is read: in [charset] (a Java charset name, `US-ASCII` to refuse
 * anything else) instead of by the char's width, and within [maxBytes] instead of [DataFormat.MAX_STRING_BYTES].
 * On a list it holds for every element.
 */
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
@Target(AnnotationTarget.PROPERTY)
annotation class Text(val charset: String = "", val maxBytes: Int = DataFormat.MAX_STRING_BYTES)

/** A pointer field marked so reads as what it points at, null where [Ptr.deref] would be. */
@OptIn(ExperimentalSerializationApi::class)
@SerialInfo
@Target(AnnotationTarget.PROPERTY)
annotation class Deref

/**
 * A typed pointer field: the [address] it holds, and what it points at decoded on first [deref], so a
 * cycle in memory is no infinite read. Two are equal when they hold the same address.
 */
@Serializable(with = Ptr.Serializer::class)
class Ptr<T>(val address: Address, read: () -> T?) {
    private val pointee by lazy(read)

    /** The pointee as a [T]; null for a null pointer or one whose pointee doesn't lie wholly in initialized memory. */
    fun deref(): T? = pointee

    override fun equals(other: Any?) = other is Ptr<*> && other.address == address
    override fun hashCode() = address.hashCode()
    override fun toString() = "Ptr($address)"

    class Serializer<T>(private val target: KSerializer<T>) : KSerializer<Ptr<T>> {
        override val descriptor =
            PrimitiveSerialDescriptor("ghistabs.Ptr<${target.descriptor.serialName}>", PrimitiveKind.LONG)
        override fun deserialize(decoder: Decoder) = DataFormat.pointer(decoder, target)
        override fun serialize(encoder: Encoder, value: Ptr<T>) = DataFormat.decodeOnly()
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
 * `program.dataAt(addr, it)?.value` or [Program.valueAt] hands back the class. That holds for pseudo data
 * and for a field of another such structure; laid in a listing, it resolves to a plain structure,
 * whose data [decode] still reads.
 *
 * A subclass that lays its fields in `init` takes the `(dtm)` constructor: the structure is named after
 * the subclass and decodes the type argument it passes, which must be `@Serializable`.
 */
open class SerialStructure<T : Any>(dtm: DataTypeManager? = null, type: Type? = null, name: String? = null) :
    StructureDataType(name ?: "SerialStructure", 0, dtm) {
    private val valueType = type
        ?: (javaClass.genericSuperclass as? ParameterizedType)?.actualTypeArguments?.single()
        ?: error("${javaClass.simpleName} must extend SerialStructure<Value> directly")

    @Suppress("UNCHECKED_CAST")
    private val deserializer = DataFormat.serializersModule.serializer(valueType) as KSerializer<T>

    private val valueClass = ((valueType as? ParameterizedType)?.rawType ?: valueType) as Class<*>

    init {
        if (name == null) setName(javaClass.simpleName)
    }

    override fun getValue(buf: MemBuffer, settings: Settings?, length: Int): T? =
        (buf as? Data ?: buf.dataHere(this))?.let { DataFormat.decode(deserializer, it) }

    override fun getValueClass(settings: Settings?) = valueClass

    // Ghidra clones a structure into each manager or composite that takes it, which would drop the decoder.
    override fun clone(dtm: DataTypeManager?) = if (dtm == dataTypeManager) this else copy(dtm)

    override fun copy(dtm: DataTypeManager?) = SerialStructure<T>(dtm, valueType, name).also {
        it.description = description
        it.replaceWith(this)
    }

    companion object {
        /** A [SerialStructure] for [T], laid out by [layout]. */
        @OptIn(ExperimentalStdlibApi::class)
        inline operator fun <reified T : Any> invoke(
            name: String,
            dtm: DataTypeManager? = null,
            layout: StructureDataType.() -> Unit,
        ) = SerialStructure<T>(dtm, typeOf<T>().javaType, name).apply(layout)
    }
}

/** This composite as a [T]; see [DataFormat]. */
inline fun <reified T> Data.decode(): T = DataFormat.decode(this)

/** [dt] laid at [addr] ([dataAt]) as a [T], or null if it can't be read there. */
inline fun <reified T> Program.decodeAt(addr: Address, dt: DataType): T? = dataAt(addr, dt)?.decode()
