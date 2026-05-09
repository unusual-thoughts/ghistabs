package ghistabs

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace

/**
 * Test helper: Fake Address implementation for mocking.
 * Used across multiple test files to avoid redeclaration.
 */
data class FakeAddress(
    val addrOffset: Long,
) : Address {
    override fun getOffset(): Long = addrOffset

    override fun getAddressSpace(): AddressSpace = error("not implemented in test")

    override fun hasSameAddressSpace(addr: Address?): Boolean = error("not implemented in test")

    override fun compareTo(other: Address?): Int = addrOffset.compareTo((other as FakeAddress).addrOffset)

    override fun getNewAddress(offset: Long): Address = FakeAddress(offset)

    override fun getNewAddress(
        offset: Long,
        isAddressableWordOffset: Boolean,
    ): Address = error("not implemented in test")

    override fun getNewTruncatedAddress(
        offset: Long,
        isAddressableWordOffset: Boolean,
    ): Address = error("not implemented in test")

    override fun getPointerSize(): Int = error("not implemented in test")

    override fun next(): Address = error("not implemented in test")

    override fun previous(): Address = error("not implemented in test")

    override fun getOffsetAsBigInteger(): java.math.BigInteger = error("not implemented in test")

    override fun getUnsignedOffset(): Long = error("not implemented in test")

    override fun getAddressableWordOffset(): Long = error("not implemented in test")

    override fun getSize(): Int = error("not implemented in test")

    override fun subtract(address: Address?): Long = error("not implemented in test")

    override fun subtract(offset: Long): Address = error("not implemented in test")

    override fun subtractWrap(offset: Long): Address = error("not implemented in test")

    override fun subtractWrapSpace(offset: Long): Address = error("not implemented in test")

    override fun subtractNoWrap(offset: Long): Address = error("not implemented in test")

    override fun addWrap(offset: Long): Address = error("not implemented in test")

    override fun addWrapSpace(offset: Long): Address = error("not implemented in test")

    override fun addNoWrap(offset: Long): Address = error("not implemented in test")

    override fun addNoWrap(offset: java.math.BigInteger?): Address = error("not implemented in test")

    override fun add(offset: Long): Address = FakeAddress(addrOffset + offset)

    override fun isSuccessor(address: Address?): Boolean = error("not implemented in test")

    override fun getPhysicalAddress(): Address = error("not implemented in test")

    override fun isMemoryAddress(): Boolean = error("not implemented in test")

    override fun isLoadedMemoryAddress(): Boolean = error("not implemented in test")

    override fun isNonLoadedMemoryAddress(): Boolean = error("not implemented in test")

    override fun isStackAddress(): Boolean = error("not implemented in test")

    override fun isUniqueAddress(): Boolean = error("not implemented in test")

    override fun isConstantAddress(): Boolean = error("not implemented in test")

    override fun isHashAddress(): Boolean = error("not implemented in test")

    override fun isRegisterAddress(): Boolean = error("not implemented in test")

    override fun isVariableAddress(): Boolean = error("not implemented in test")

    override fun isExternalAddress(): Boolean = error("not implemented in test")

    override fun getAddress(addressString: String?): Address = error("not implemented in test")

    override fun toString(includeAddressSpace: Boolean): String = "0x${addrOffset.toString(16)}"

    override fun toString(
        showAddressSpace: Boolean,
        includeAddressSpace: Boolean,
    ): String = "0x${addrOffset.toString(16)}"

    override fun toString(
        padWithZeros: Boolean,
        minHexDigits: Int,
    ): String = "0x${addrOffset.toString(16)}"

    override fun toString(addressString: String?): String = "0x${addrOffset.toString(16)}"

    override fun toString(): String = "0x${addrOffset.toString(16)}"

    override fun equals(other: Any?): Boolean = (this === other) || (other is FakeAddress && addrOffset == other.addrOffset)

    override fun hashCode(): Int = addrOffset.hashCode()
}
