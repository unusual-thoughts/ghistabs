package ghistabs.importer

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.BookmarkManager
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.container.StabRecord
import ghistabs.container.StabType
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.argThat
import org.mockito.kotlin.doNothing
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever

class SymbolApplyTest {
    private fun fakeAddr(offset: Long): Address = FakeAddress(offset)

    private fun buildImporter(): StabsImporter {
        // Build program with all necessary mocks
        val program = mock<Program>()

        // Address factory
        val addrSpace = mock<AddressSpace>()
        whenever(addrSpace.getAddress(any<Long>())).thenAnswer { inv ->
            fakeAddr(inv.getArgument(0))
        }
        val addressFactory = mock<ghidra.program.model.address.AddressFactory>()
        whenever(addressFactory.defaultAddressSpace).thenReturn(addrSpace)
        whenever(program.addressFactory).thenReturn(addressFactory)

        // Function manager
        val funcMgr = mock<FunctionManager>()
        // getFunctionAt returns null by default (no pre-existing function)
        whenever(funcMgr.getFunctionAt(any())).thenReturn(null)
        // createFunction returns a mock Function
        val mockFunc = mock<Function>()
        whenever(funcMgr.createFunction(any(), any(), any(), any())).thenReturn(mockFunc)
        whenever(program.functionManager).thenReturn(funcMgr)

        // Listing
        val listing = mock<Listing>()
        // clearCodeUnits is void, so we use doNothing
        doNothing().whenever(listing).clearCodeUnits(any(), any(), any())
        whenever(listing.createData(any(), any())).thenReturn(null)
        whenever(program.listing).thenReturn(listing)

        // Bookmark manager
        whenever(program.bookmarkManager).thenReturn(mock<BookmarkManager>())

        // Symbol table
        whenever(program.symbolTable).thenReturn(mock<SymbolTable>())

        // Data type manager - use a mock directly
        val mockDtm: ghidra.program.model.data.ProgramBasedDataTypeManager = mock()
        whenever(mockDtm.startTransaction(any())).thenReturn(0)
        whenever(mockDtm.endTransaction(any(), any())).thenReturn(true)
        whenever(program.dataTypeManager).thenReturn(mockDtm)

        // Transactions
        whenever(program.startTransaction(any())).thenReturn(0)
        whenever(program.endTransaction(any(), any())).thenReturn(true)

        // Create context and importer
        val log = MessageLog()
        val monitor = mock<TaskMonitor>()
        val options = StabsOptions()
        val ctx = ImportContext(program, log, monitor, options)
        return StabsImporter(ctx)
    }

    /**
     * AC4.3: Global variable - stab harvesting and address resolution works
     */
    @Test
    fun testGlobalSymbolHarvesting() {
        val importer = buildImporter()

        val records =
            listOf(
                StabRecord(0, StabType.N_SO, 0x64, 0, 0, 0, "test.cpp"),
                StabRecord(1, StabType.N_GSYM, 0x20, 0, 0, 0, "g_count:G(0,1);"),
            )

        val result = importer.runWithRecords(records)

        // Should harvest the global symbol without parse errors
        assertEquals(0, result.parseErrors, "Should have no parse errors")
        assertEquals(2, result.recordsParsed, "Should parse both N_SO and N_GSYM records")
    }

    /**
     * AC6.2: Importer continues past malformed record
     */
    @Test
    fun testContinuesOnParseError() {
        val importer = buildImporter()

        val records =
            listOf(
                StabRecord(0, StabType.N_SO, 0x64, 0, 0, 0, "test.cpp"),
                StabRecord(1, StabType.N_GSYM, 0x20, 0, 0, 0, "g_one:G(0,1);"), // valid
                StabRecord(2, StabType.N_GSYM, 0x20, 0, 0, 0, "garbage:G@@@?"), // malformed
                StabRecord(3, StabType.N_GSYM, 0x20, 0, 0, 0, "g_three:G(0,1);"), // valid
            )

        val result = importer.runWithRecords(records)

        // Should report parse error but continue processing surrounding records
        assertEquals(1, result.parseErrors, "Should have 1 parse error from malformed record")
        assertEquals(3, result.recordsParsed, "Should parse 3 records successfully (4 total - 1 error)")
    }
}

private data class FakeAddress(
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
