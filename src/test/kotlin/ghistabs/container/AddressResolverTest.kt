package ghistabs.container

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class AddressResolverTest {
    private lateinit var labelStore: FakeLabelStore
    private lateinit var resolver: AddressResolver

    @BeforeEach
    fun setUp() {
        labelStore = FakeLabelStore()
        resolver = AddressResolver(labelStore)
    }

    @Test
    fun testRecordFromStabCreatesImportedLabel() {
        val addr = FakeAddress(0x1000)
        val name = "test_function"
        assertTrue(labelStore.getSymbols(addr).isEmpty())
        resolver.recordFromStab(name, addr)
        val symbols = labelStore.getSymbols(addr)
        assertEquals(1, symbols.size)
        assertEquals(name, symbols[0].name)
        assertEquals(SourceType.IMPORTED, symbols[0].source)
    }

    @Test
    fun testRecordFromStabIsIdempotent() {
        val addr = FakeAddress(0x2000)
        val name = "another_function"
        resolver.recordFromStab(name, addr)
        val firstCall = labelStore.getSymbols(addr)
        assertEquals(1, firstCall.size)
        resolver.recordFromStab(name, addr)
        val secondCall = labelStore.getSymbols(addr)
        assertEquals(1, secondCall.size)
        assertEquals(name, secondCall[0].name)
    }

    @Test
    fun testRecordFromStabDoesNotOverwriteExistingSymbol() {
        val addr = FakeAddress(0x3000)
        val name = "existing_symbol"
        labelStore.createLabel(addr, name, SourceType.USER_DEFINED)
        val existingSymbols = labelStore.getSymbols(addr)
        assertEquals(1, existingSymbols.size)
        assertEquals(SourceType.USER_DEFINED, existingSymbols[0].source)
        resolver.recordFromStab(name, addr)
        val symbols = labelStore.getSymbols(addr)
        assertEquals(1, symbols.size)
        assertEquals(SourceType.USER_DEFINED, symbols[0].source)
    }

    @Test
    fun testResolvePrefersStagMap() {
        val stabAddr = FakeAddress(0x4000)
        val symbolAddr = FakeAddress(0x5000)
        val name = "conflicting_name"
        resolver.recordFromStab(name, stabAddr)
        labelStore.createLabel(symbolAddr, name, SourceType.ANALYSIS)
        val result = resolver.resolve(name)
        assertEquals(stabAddr, result)
    }

    @Test
    fun testResolveDefaultsToSymbolTable() {
        val addr = FakeAddress(0x6000)
        val name = "table_symbol"
        labelStore.createLabel(addr, name, SourceType.ANALYSIS)
        val result = resolver.resolve(name)
        assertEquals(addr, result)
    }

    @Test
    fun testResolveReturnsNullWhenNotFound() {
        val result = resolver.resolve("nonexistent_symbol")
        assertNull(result)
    }

    @Test
    fun testStrippedBinaryTolerance() {
        val emptyLabelStore = FakeLabelStore()
        val emptyResolver = AddressResolver(emptyLabelStore)
        val addr = FakeAddress(0x7000)
        val name = "foo"
        assertTrue(emptyLabelStore.getSymbols(addr).isEmpty())
        emptyResolver.recordFromStab(name, addr)
        val symbols = emptyLabelStore.getSymbols(addr)
        assertEquals(1, symbols.size)
        assertEquals(name, symbols[0].name)
        assertEquals(SourceType.IMPORTED, symbols[0].source)
        val resolved = emptyResolver.resolve(name)
        assertEquals(addr, resolved)
    }

    @Test
    fun testRecordFromStabIgnoresBlankName() {
        val addr = FakeAddress(0x8000)
        val blankName = "   "
        resolver.recordFromStab(blankName, addr)
        val symbols = labelStore.getSymbols(addr)
        assertEquals(0, symbols.size)
    }
}

private data class FakeAddress(
    val addrOffset: Long,
) : Address {
    override fun getOffset(): Long = addrOffset

    override fun getAddressSpace(): AddressSpace = error("not implemented in test")

    override fun hasSameAddressSpace(addr: Address?): Boolean = error("not implemented in test")

    override fun compareTo(other: Address?): Int = addrOffset.compareTo((other as FakeAddress).addrOffset)

    override fun getNewAddress(offset: Long): Address = error("not implemented in test")

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

    override fun add(offset: Long): Address = error("not implemented in test")

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

private fun mockSymbol(
    name: String,
    addr: Address,
    source: SourceType,
): Symbol {
    val sym = mock<Symbol>()
    whenever(sym.name).thenReturn(name)
    whenever(sym.address).thenReturn(addr)
    whenever(sym.source).thenReturn(source)
    return sym
}

private class FakeLabelStore : LabelStore {
    private val symbolsByAddress: MutableMap<Long, MutableList<Symbol>> = mutableMapOf()
    private val symbolsByName: MutableMap<String, MutableList<Symbol>> = mutableMapOf()

    override fun createLabel(
        addr: Address,
        name: String,
        source: SourceType,
    ): Symbol {
        val key = (addr as FakeAddress).addrOffset
        val symbol = mockSymbol(name, addr, source)
        symbolsByAddress.computeIfAbsent(key) { mutableListOf() }.add(symbol)
        if (name.isNotBlank()) {
            symbolsByName.computeIfAbsent(name) { mutableListOf() }.add(symbol)
        }
        return symbol
    }

    override fun getSymbols(addr: Address): List<Symbol> {
        val key = (addr as FakeAddress).addrOffset
        return symbolsByAddress[key]?.toList() ?: emptyList()
    }

    override fun getSymbols(name: String): List<Symbol> {
        if (name.isBlank()) return emptyList()
        return symbolsByName[name]?.toList() ?: emptyList()
    }
}
