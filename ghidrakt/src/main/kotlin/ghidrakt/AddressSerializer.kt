package ghidrakt

import ghidra.program.model.address.Address
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** An [Address] as its space's name and its offset. Serialize-only. */
class AddressSerializer : KSerializer<Address> {
    @Serializable
    private data class AddressSurrogate(val space: String, val offset: Long) {
        constructor(addr: Address) : this(addr.addressSpace.name, addr.offset)
    }

    override val descriptor =
        SerialDescriptor("ghidra.program.model.address.Address", AddressSurrogate.serializer().descriptor)

    override fun serialize(encoder: Encoder, value: Address) =
        encoder.encodeSerializableValue(AddressSurrogate.serializer(), AddressSurrogate(value))

    override fun deserialize(decoder: Decoder) =
        throw UnsupportedOperationException("AddressSerializer is serialize-only")
}
