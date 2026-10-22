package ghistabs

import ghidra.framework.options.GProperties
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.AbstractDecoder
import kotlinx.serialization.encoding.AbstractEncoder
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import kotlinx.serialization.modules.EmptySerializersModule
import kotlinx.serialization.modules.SerializersModule

/**
 * A `@Serializable` class onto [GProperties], the store a [ghidra.framework.options.CustomOption] reads and
 * writes, so one needs no hand-written `readState`/`writeState`. Its properties go under their names:
 * a primitive as GProperties' own type (a char or enum as a string), a nested class as nested
 * [GProperties], a list as nested ones keyed `0`, `1`, …, a map as nested ones keyed by the key's string.
 * A null is an absent key.
 *
 * Map entries read back in GProperties' order, which sorts its keys as strings, not in the order they
 * went in. Keys the class doesn't name are ignored, which is what lets the class name a custom option
 * stores beside its state go by.
 */
@OptIn(ExperimentalSerializationApi::class)
object GPropertiesFormat {
    fun <T> encode(serializer: SerializationStrategy<T>, value: T, into: GProperties) =
        Writer(into, null).encodeSerializableValue(serializer, value)

    fun <T> decode(deserializer: DeserializationStrategy<T>, from: GProperties): T =
        Reader(from, null).decodeSerializableValue(deserializer)

    inline fun <reified T> encode(value: T, into: GProperties) = encode(serializer<T>(), value, into)

    inline fun <reified T> decode(from: GProperties): T = decode(serializer<T>(), from)

    private const val NESTED = "GProperties"

    /** Writes the structure [level] into [props]; [level] null is the value itself, before its structure begins. */
    private class Writer(
        private val props: GProperties,
        private val level: SerialDescriptor?,
        private val attach: () -> Unit = {},
    ) : AbstractEncoder() {
        override val serializersModule: SerializersModule = EmptySerializersModule()
        private var tag = ""
        private var keyNext = false
        private var mapKey = ""

        override fun encodeElement(descriptor: SerialDescriptor, index: Int): Boolean {
            when (descriptor.kind) {
                StructureKind.LIST -> tag = index.toString()
                StructureKind.MAP -> if (index % 2 == 0) keyNext = true else tag = mapKey
                else -> tag = descriptor.getElementName(index)
            }
            return true
        }

        override fun beginStructure(descriptor: SerialDescriptor): CompositeEncoder {
            if (keyNext) throw SerializationException("A map key must be a primitive or an enum")
            if (level == null) return Writer(props, descriptor)
            val name = tag
            // Its own name is the XML element it saves as, so not the key: `0` is no XML name.
            val child = GProperties(NESTED)
            return Writer(child, descriptor) { props.putGProperties(name, child) }
        }

        override fun endStructure(descriptor: SerialDescriptor) = attach()

        override fun encodeNull() {
            if (keyNext) throw SerializationException("A map key can't be null")
        }

        override fun encodeEnum(enumDescriptor: SerialDescriptor, index: Int) =
            encodeValue(enumDescriptor.getElementName(index))

        override fun encodeValue(value: Any) {
            if (keyNext) {
                keyNext = false
                mapKey = value.toString()
                return
            }
            if (level == null) {
                throw SerializationException("GProperties hold a structure, not a ${value::class.simpleName}")
            }
            when (value) {
                is Boolean -> props.putBoolean(tag, value)
                is Byte -> props.putByte(tag, value)
                is Short -> props.putShort(tag, value)
                is Int -> props.putInt(tag, value)
                is Long -> props.putLong(tag, value)
                is Float -> props.putFloat(tag, value)
                is Double -> props.putDouble(tag, value)
                is Char -> props.putString(tag, value.toString())
                is String -> props.putString(tag, value)
                else -> throw SerializationException("GProperties can't hold a ${value::class.simpleName}")
            }
        }
    }

    /** Reads the structure [level] out of [props]; [level] null is the value itself, before its structure begins. */
    // A decodeX per primitive is the decoder's contract, not a class doing too much.
    @Suppress("TooManyFunctions")
    private class Reader(private val props: GProperties, private val level: SerialDescriptor?) : AbstractDecoder() {
        override val serializersModule: SerializersModule = EmptySerializersModule()
        private var index = -1
        private var tag = ""
        private var keyNext = false
        private val names: Array<String> by lazy { props.names }

        override fun decodeElementIndex(descriptor: SerialDescriptor): Int {
            while (++index < when (descriptor.kind) {
                    StructureKind.LIST -> names.size
                    StructureKind.MAP -> names.size * 2
                    else -> descriptor.elementsCount
                }
            ) {
                when (descriptor.kind) {
                    StructureKind.LIST -> tag = index.toString()

                    StructureKind.MAP -> if (index % 2 == 0) keyNext = true else tag = names[index / 2]

                    else -> {
                        tag = descriptor.getElementName(index)
                        // An absent key is a null, unless the property has a default to fall back on.
                        if (!props.hasValue(tag) && descriptor.isElementOptional(index)) continue
                    }
                }
                return index
            }
            return CompositeDecoder.DECODE_DONE
        }

        override fun beginStructure(descriptor: SerialDescriptor): CompositeDecoder {
            if (keyNext) throw SerializationException("A map key must be a primitive or an enum")
            if (level == null) return Reader(props, descriptor)
            return Reader(props.getGProperties(tag) ?: throw missing(), descriptor)
        }

        override fun decodeNotNullMark() = keyNext || props.hasValue(tag)

        override fun decodeNull(): Nothing? = null

        /** The map key this element is, when it is one. */
        private fun key(): String? = if (keyNext) names[index / 2].also { keyNext = false } else null

        // Not props.name: 10.4's GProperties has no getName.
        private fun missing() = SerializationException("No '$tag' in ${level?.serialName}")

        override fun decodeBoolean() = key()?.toBooleanStrict() ?: props.getBoolean(tag, false)
        override fun decodeByte() = key()?.toByte() ?: props.getByte(tag, 0)
        override fun decodeShort() = key()?.toShort() ?: props.getShort(tag, 0)
        override fun decodeInt() = key()?.toInt() ?: props.getInt(tag, 0)
        override fun decodeLong() = key()?.toLong() ?: props.getLong(tag, 0)
        override fun decodeFloat() = key()?.toFloat() ?: props.getFloat(tag, 0f)
        override fun decodeDouble() = key()?.toDouble() ?: props.getDouble(tag, 0.0)
        override fun decodeChar() = decodeString().single()
        override fun decodeString() = key() ?: props.getString(tag, null) ?: throw missing()

        override fun decodeEnum(enumDescriptor: SerialDescriptor): Int {
            val name = decodeString()
            return enumDescriptor.getElementIndex(name).takeIf { it != CompositeDecoder.UNKNOWN_NAME }
                ?: throw SerializationException("No ${enumDescriptor.serialName} named '$name'")
        }
    }
}
