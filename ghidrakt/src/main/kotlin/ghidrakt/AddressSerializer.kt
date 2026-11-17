package ghidrakt

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * An [Address] as Ghidra prints it (`00401000`, `EXTERNAL:00000001`), read back as a [DetachedAddresses] one:
 * a model written out with a program open reads back with none.
 */
object AddressSerializer : KSerializer<Address> {
    override val descriptor = PrimitiveSerialDescriptor("ghidra.program.model.address.Address", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Address) = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): Address = DetachedAddresses.parse(decoder.decodeString())
}

/**
 * Addresses with no program behind them: each space by its name, 64 bits wide, the unnamed one [DEFAULT].
 * Two of them are equal when their spaces' names and their offsets are, but never equal a program's own
 * address, whose space is as wide as its language makes it: compare those by [Address.offset].
 */
object DetachedAddresses {
    /** The space an address printed without one is in, named as a program's default space usually is. */
    const val DEFAULT = "ram"

    private val spaces = ConcurrentHashMap<String, AddressSpace>()
    private val ids = AtomicInteger()

    fun space(name: String): AddressSpace = spaces.computeIfAbsent(name) {
        GenericAddressSpace(it, 64, AddressSpace.TYPE_RAM, ids.getAndIncrement(), it != DEFAULT)
    }

    fun at(offset: Long, space: String = DEFAULT): Address = space(space).getAddress(offset)

    /** [text] as [AddressSerializer] writes it: hex digits, after a space's name and a colon unless [DEFAULT]. */
    fun parse(text: String): Address = at(
        java.lang.Long.parseUnsignedLong(text.substringAfterLast(':'), 16),
        text.substringBefore(':', DEFAULT),
    )
}
