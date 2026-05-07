package ghistabs.container

import ghidra.program.model.address.Address
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock

/**
 * Ring-2 tests for AddressResolver.
 * Tests label creation, idempotence, fallback behavior, and stripped-binary tolerance (AC6.1).
 *
 * Uses a custom in-memory LabelStore plus minimal Address/Symbol fakes leveraging Mockito.
 */
class AddressResolverTest {
    private lateinit var labelStore: FakeLabelStore
    private lateinit var resolver: AddressResolver

    @BeforeEach
    fun setUp() {
        labelStore = FakeLabelStore()
        resolver = AddressResolver(labelStore)
    }

    /**
     * Test: recordFromStab creates an IMPORTED label when no symbol exists at the address.
     */
    @Test
    fun testRecordFromStabCreatesImportedLabel() {
        val addr = FakeAddress(0x1000)
        val name = "test_function"

        // Verify no symbol exists yet
        assertTrue(labelStore.getSymbols(addr).isEmpty())

        // Record the symbol
        resolver.recordFromStab(name, addr)

        // Verify IMPORTED label was created
        val symbols = labelStore.getSymbols(addr)
        assertEquals(1, symbols.size, "Should have created one symbol")
        val symbol = symbols[0]
        assertEquals(name, symbol.name, "Symbol name should match")
        assertEquals(SourceType.IMPORTED, symbol.source, "Symbol should be IMPORTED source")
    }

    /**
     * Test: recordFromStab is a no-op when a symbol already exists at the address with the same name.
     */
    @Test
    fun testRecordFromStabIsIdempotent() {
        val addr = FakeAddress(0x2000)
        val name = "another_function"

        // First call creates the label
        resolver.recordFromStab(name, addr)
        val firstCall = labelStore.getSymbols(addr)
        assertEquals(1, firstCall.size)

        // Second call with same (name, addr) should be a no-op
        resolver.recordFromStab(name, addr)
        val secondCall = labelStore.getSymbols(addr)
        assertEquals(1, secondCall.size, "Should still have exactly one symbol (idempotent)")
        assertEquals(name, secondCall[0].name)
    }

    /**
     * Test: recordFromStab does NOT overwrite a USER_DEFINED or ANALYSIS symbol
     * with the same name (it just records the mapping).
     */
    @Test
    fun testRecordFromStabDoesNotOverwriteExistingSymbol() {
        val addr = FakeAddress(0x3000)
        val name = "existing_symbol"

        // Create a USER_DEFINED symbol first
        labelStore.createLabel(addr, name, SourceType.USER_DEFINED)

        val existingSymbols = labelStore.getSymbols(addr)
        assertEquals(1, existingSymbols.size)
        assertEquals(SourceType.USER_DEFINED, existingSymbols[0].source)

        // Try to record a stab-derived symbol at the same address with the same name
        resolver.recordFromStab(name, addr)

        // Should still have the original USER_DEFINED symbol, unchanged
        val symbols = labelStore.getSymbols(addr)
        assertEquals(1, symbols.size, "Should still have original symbol")
        assertEquals(SourceType.USER_DEFINED, symbols[0].source, "Source type should not change")
    }

    /**
     * Test: resolve returns the stab-derived address when both the stab map
     * and the label store are populated (stab map wins).
     */
    @Test
    fun testResolvePrefersStagMap() {
        val stabAddr = FakeAddress(0x4000)
        val symbolAddr = FakeAddress(0x5000)
        val name = "conflicting_name"

        // Create two different symbols with the same name at different addresses
        resolver.recordFromStab(name, stabAddr)
        labelStore.createLabel(symbolAddr, name, SourceType.ANALYSIS)

        // Resolve should return the stab-derived address (it wins)
        val result = resolver.resolve(name)
        assertEquals(stabAddr, result, "Should resolve to stab-derived address")
    }

    /**
     * Test: resolve falls back to labelStore.getSymbols(name)
     * when the stab map is empty.
     */
    @Test
    fun testResolveDefaultsToSymbolTable() {
        val addr = FakeAddress(0x6000)
        val name = "table_symbol"

        // Create a symbol in the label store only (not via resolver)
        labelStore.createLabel(addr, name, SourceType.ANALYSIS)

        // Resolve should find it in the label store
        val result = resolver.resolve(name)
        assertEquals(addr, result, "Should resolve from label store")
    }

    /**
     * Test: resolve returns null when neither source has the name.
     */
    @Test
    fun testResolveReturnsNullWhenNotFound() {
        val result = resolver.resolve("nonexistent_symbol")
        assertNull(result, "Should return null for missing symbol")
    }

    /**
     * Test: Stripped-binary tolerance (AC6.1).
     * Build a LabelStore with NO COFF/ELF symbols. After calling recordFromStab("foo", addr),
     * assert labelStore.getSymbols("foo") returns a single symbol with SourceType.IMPORTED.
     */
    @Test
    fun testStrippedBinaryTolerance() {
        // Create a clean label store with no symbols
        val emptyStore = FakeLabelStore()
        val emptyResolver = AddressResolver(emptyStore)

        val addr = FakeAddress(0x7000)
        val name = "foo"

        // Verify label store has no pre-existing symbols at this address
        assertTrue(emptyStore.getSymbols(addr).isEmpty())

        // Call recordFromStab on the empty label store
        emptyResolver.recordFromStab(name, addr)

        // Verify that an IMPORTED label was created
        val symbols = emptyStore.getSymbols(addr)
        assertEquals(1, symbols.size, "Should have created exactly one symbol")
        assertEquals(name, symbols[0].name, "Symbol name should be 'foo'")
        assertEquals(SourceType.IMPORTED, symbols[0].source, "Should be IMPORTED source")

        // Also verify we can resolve it
        val resolved = emptyResolver.resolve(name)
        assertEquals(addr, resolved, "Should resolve 'foo' to the recorded address")
    }

    /**
     * Test: recordFromStab with blank name is handled gracefully.
     */
    @Test
    fun testRecordFromStabIgnoresBlankName() {
        val addr = FakeAddress(0x8000)
        val blankName = "   "

        // This should be a no-op (or at least not create a label)
        resolver.recordFromStab(blankName, addr)

        // Verify no symbol was created at this address
        val symbols = labelStore.getSymbols(addr)
        assertEquals(0, symbols.size, "Should not create label for blank name")
    }
}

/**
 * Minimal fake Address that provides only the offset needed for testing.
 * Uses data class for automatic equals/hashCode based on offset.
 */
private data class FakeAddress(
    val offset: Long,
) : Address {
    override fun getOffset(): Long = offset

    override fun getAddressSpace() = error("not implemented in test")

    override fun hasSameAddressSpace(addr: Address?) = error("not implemented in test")

    override fun compareTo(other: Address?) = error("not implemented in test")

    override fun getNewAddress(offset: Long) = error("not implemented in test")

    override fun getNewAddress(
        offset: Long,
        isAddressableWordOffset: Boolean,
    ) = error("not implemented in test")

    override fun getNewTruncatedAddress(
        offset: Long,
        isAddressableWordOffset: Boolean,
    ) = error("not implemented in test")

    override fun getPointerSize() = error("not implemented in test")

    override fun next() = error("not implemented in test")

    override fun previous() = error("not implemented in test")

    override fun getOffsetAsBigInteger() = error("not implemented in test")

    override fun getUnsignedOffset() = error("not implemented in test")

    override fun getAddressableWordOffset() = error("not implemented in test")

    override fun getSize() = error("not implemented in test")

    override fun subtract(address: Address?) = error("not implemented in test")

    override fun subtract(offset: Long) = error("not implemented in test")

    override fun subtractWrap(offset: Long) = error("not implemented in test")

    override fun subtractWrapSpace(offset: Long) = error("not implemented in test")

    override fun subtractNoWrap(offset: Long) = error("not implemented in test")

    override fun addWrap(offset: Long) = error("not implemented in test")

    override fun addWrapSpace(offset: Long) = error("not implemented in test")

    override fun addNoWrap(offset: Long) = error("not implemented in test")

    override fun addNoWrap(offset: java.math.BigInteger?) = error("not implemented in test")

    override fun add(offset: Long) = error("not implemented in test")

    override fun isSuccessor(address: Address?) = error("not implemented in test")

    override fun getPhysicalAddress() = error("not implemented in test")

    override fun isMemoryAddress() = error("not implemented in test")

    override fun isLoadedMemoryAddress() = error("not implemented in test")

    override fun isNonLoadedMemoryAddress() = error("not implemented in test")

    override fun isStackAddress() = error("not implemented in test")

    override fun isUniqueAddress() = error("not implemented in test")

    override fun isConstantAddress() = error("not implemented in test")

    override fun isHashAddress() = error("not implemented in test")

    override fun isRegisterAddress() = error("not implemented in test")

    override fun isVariableAddress() = error("not implemented in test")

    override fun isExternalAddress() = error("not implemented in test")

    override fun getAddress(addressString: String?) = error("not implemented in test")

    override fun toString(includeAddressSpace: Boolean) = "0x${offset.toString(16)}"

    override fun toString(
        showAddressSpace: Boolean,
        includeAddressSpace: Boolean,
    ) = error("not implemented in test")

    override fun toString(
        padWithZeros: Boolean,
        minHexDigits: Int,
    ) = error("not implemented in test")
}

/**
 * Minimal fake Symbol that wraps name, address, and source type.
 * Uses delegation to a Mockito mock to avoid implementing 100+ abstract methods.
 */
private data class FakeSymbol(
    override val name: String,
    val addr: Address,
    override val source: SourceType,
) : Symbol by mock() {
    override fun getAddress(): Address = addr

    override fun getName(): String = name

    override fun getSource(): SourceType = source
}

/**
 * In-memory LabelStore that stores symbols indexed by address and by name.
 * Implements only the LabelStore interface needed by AddressResolver.
 */
private class FakeLabelStore : LabelStore {
    private val symbolsByAddress: MutableMap<Long, MutableList<FakeSymbol>> = mutableMapOf()
    private val symbolsByName: MutableMap<String, MutableList<FakeSymbol>> = mutableMapOf()

    override fun createLabel(
        addr: Address,
        name: String,
        source: SourceType,
    ): Symbol {
        val fakeAddr = addr as FakeAddress
        val symbol = FakeSymbol(name, addr, source)
        symbolsByAddress.computeIfAbsent(fakeAddr.offset) { mutableListOf() }.add(symbol)
        if (name.isNotBlank()) {
            symbolsByName.computeIfAbsent(name) { mutableListOf() }.add(symbol)
        }
        return symbol
    }

    override fun getSymbols(addr: Address): List<Symbol> {
        val fakeAddr = addr as FakeAddress
        return symbolsByAddress[fakeAddr.offset] ?: emptyList()
    }

    override fun getSymbols(name: String): List<Symbol> {
        if (name.isBlank()) return emptyList()
        return symbolsByName[name] ?: emptyList()
    }
}
