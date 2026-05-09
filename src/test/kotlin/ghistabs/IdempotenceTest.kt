package ghistabs

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
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.container.StabRecord
import ghistabs.container.StabType
import ghistabs.importer.ImportContext
import ghistabs.importer.StabsImporter
import ghistabs.importer.StabsOptions
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doNothing
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Tests for StabsImporter idempotence.
 *
 * AC6.4: Re-running the importer (with done-flag cleared) on a fully-imported program
 * produces no duplicate types, no duplicate symbols, and byte-identical DTM/symbol state.
 *
 * Note: Full DTM state idempotence (verifying no duplicate type entries in Ghidra's
 * DTM across multiple importer runs) requires an integration test with a real Ghidra
 * program and DTM. With mocks, we verify that the importer's *parsing logic* is
 * idempotent: same input → same count of records parsed, same error count, same
 * number of types materialized.
 */
class IdempotenceTest {
    /**
     * AC6.4 (parsing idempotence): Second run with same input produces identical result counts.
     *
     * Tests that the parsing and counting logic is idempotent. With mock DTM/symbol state,
     * we cannot verify true DTM state idempotence; that is deferred to integration tests.
     */
    @Test
    fun testSecondRunProducesSameParseResults() {
        val importer = buildImporter()

        // Simple fixture: 1 N_SO, 1 N_LSYM global, 1 type definition
        val records =
            listOf(
                StabRecord(0, StabType.N_SO, 0, 0, 0, 0, "test.cpp"),
                StabRecord(1, StabType.N_LSYM, 0x100, 0, 0, 0, "g_var:G(0,1);"),
            )

        // First run
        val result1 = importer.runWithRecords(records)

        // Second run (simulates cleared done-flag)
        val result2 = importer.runWithRecords(records)

        // Both runs should produce identical parse results
        assertEquals(result1.recordsParsed, result2.recordsParsed, "Record count should match between runs")
        assertEquals(result1.parseErrors, result2.parseErrors, "Parse error count should match between runs")
        assertEquals(result1.typesMaterialised, result2.typesMaterialised, "Type count should match between runs")

        // The key is that no exceptions are raised on second run
        assertTrue(result1.recordsParsed > 0, "First run should parse at least the N_SO record")
    }

    /**
     * AC6.4 (robustness): Importer handles repeated runs without exceptions.
     *
     * Verifies that calling the importer multiple times with identical input
     * does not raise exceptions, even though mock DTM doesn't track state.
     */
    @Test
    fun testRepeatedRunsDoNotThrow() {
        val importer = buildImporter()

        val records =
            listOf(
                StabRecord(0, StabType.N_SO, 0, 0, 0, 0, "test.cpp"),
                StabRecord(1, StabType.N_LSYM, 0x100, 0, 0, 0, "g_var:G(0,1);"),
                StabRecord(2, StabType.N_GSYM, 0x200, 0, 0, 0, "g_global:G(0,1);"),
            )

        // Run three times without exception
        val result1 = importer.runWithRecords(records)
        val result2 = importer.runWithRecords(records)
        val result3 = importer.runWithRecords(records)

        // All three runs should succeed with consistent results
        assertEquals(result1.parseErrors, result2.parseErrors)
        assertEquals(result2.parseErrors, result3.parseErrors)
    }

    private fun buildImporter(): StabsImporter {
        // Build program with all necessary mocks
        val program = mock<Program>()

        // Address factory
        val addrSpace = mock<AddressSpace>()
        whenever(addrSpace.getAddress(any<Long>())).thenAnswer { inv ->
            FakeAddress(inv.getArgument(0))
        }
        val addressFactory = mock<ghidra.program.model.address.AddressFactory>()
        whenever(addressFactory.defaultAddressSpace).thenReturn(addrSpace)
        whenever(program.addressFactory).thenReturn(addressFactory)

        // Function manager
        val funcMgr = mock<FunctionManager>()
        whenever(funcMgr.getFunctionAt(any())).thenReturn(null)
        val mockFunc = mock<Function>()
        whenever(funcMgr.createFunction(any(), any(), any(), any())).thenReturn(mockFunc)
        whenever(program.functionManager).thenReturn(funcMgr)

        // Listing
        val listing = mock<Listing>()
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
}
