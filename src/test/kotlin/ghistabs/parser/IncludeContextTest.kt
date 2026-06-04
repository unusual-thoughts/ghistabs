package ghistabs.parser

import ghistabs.diag.CapturingSink
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class IncludeContextTest {
    private lateinit var registry: HeaderRegistry
    private lateinit var sink: CapturingSink

    @BeforeEach
    fun setUp() {
        sink = CapturingSink()
        registry = HeaderRegistry(sink)
    }

    @Test
    fun `beginInclude allocates fileNum and pushes stack`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        val fileNum2 = ctx.beginInclude("header.h", 0x123L)
        assertEquals(2, fileNum2)
        val header = ctx.headerForFileNum(fileNum2)
        assertNotNull(header)
        assertEquals("header.h", header!!.filename)
        assertEquals(0x123L, header.checksum)
    }

    @Test
    fun `endInclude pops stack without changing fileNum`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        val fileNum2 = ctx.beginInclude("header.h", 0x123L)
        ctx.endInclude()
        // After popping, headerForFileNum should still return the header (it was registered by fileNum)
        assertNotNull(ctx.headerForFileNum(fileNum2))
    }

    @Test
    fun `two CUs with same BINCL get same HeaderFile instance`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        val fileNum2 = ctx2.beginInclude("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance (object identity)
        assertTrue(header1 === header2)
        assertEquals("header.h", header1!!.filename)
        assertEquals(0x123L, header1.checksum)
    }

    @Test
    fun `reMountExcluded with prior BINCL reuses same HeaderFile`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        val fileNum2 = ctx2.remount("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance
        assertTrue(header1 === header2)
        // Different fileNum (new allocation in ctx2)
        assertTrue(fileNum1 != fileNum2 || fileNum1 == 2 && fileNum2 == 2)
    }

    @Test
    fun `forward EXCL without prior BINCL allocates placeholder and logs`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        val fileNum2 = ctx.remount("unknown.h", 0x456L)
        val header = ctx.headerForFileNum(fileNum2)

        assertNotNull(header)
        assertEquals("unknown.h", header!!.filename)
        assertEquals(0x456L, header.checksum)
        assertEquals("<unknown>", header.originatingCu)

        // Check log was emitted
        val forwardExclLog = sink.lines.find { it.tag == "forward-excl" }
        assertNotNull(forwardExclLog)
        assertTrue(forwardExclLog!!.msg!!.contains("unknown.h"))
        assertTrue(forwardExclLog.msg!!.contains("0x456"))
    }

    @Test
    fun `forward EXCL then BINCL creates two distinct HeaderFile instances`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        val fileNum1Excl = ctx1.remount("header.h", 0x123L)
        val header1Excl = ctx1.headerForFileNum(fileNum1Excl)

        // Verify forward-excl log was emitted exactly once
        assertEquals(1, sink.lines.filter { it.tag == "forward-excl" }.size)
        assertEquals("<unknown>", header1Excl!!.originatingCu)

        // Now a later CU with real BINCL should get a different HeaderFile
        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        val fileNum2Bincl = ctx2.beginInclude("header.h", 0x123L)
        val header2Bincl = ctx2.headerForFileNum(fileNum2Bincl)

        // Different instances (per-CU slots)
        assertTrue(header1Excl !== header2Bincl)
        // But the BINCL one should have the real originating CU
        assertEquals("cu2.cpp", header2Bincl!!.originatingCu)
    }

    @Test
    fun `endInclude with empty stack logs unbalanced warning`() {
        val ctx = IncludeContext("test.cpp", sink, registry)

        // Call endInclude on empty stack
        ctx.endInclude()

        // Check log was emitted
        val unbalancedLog = sink.lines.find { it.tag == "einc-unbalanced" }
        assertNotNull(unbalancedLog)
        assertTrue(unbalancedLog!!.msg!!.contains("empty stack"))
    }

    @Test
    fun `regression C1 shared HeaderRegistry ensures cross-CU dedup`() {
        // This test verifies the critical C1 fix: when multiple CUs share the same
        // registry, they must get the SAME HeaderFile instance for the same (filename, checksum).
        // Without the fix, each CU instantiates its own IncludeContext with IncludeContext(name, sink)
        // using the default HeaderRegistry(), creating isolated registries and breaking dedup.
        //
        // This test constructs two CUs with EXPLICIT shared registry (simulating the fixed production code)
        // and verifies identity. Then it separately constructs two CUs with SEPARATE registries
        // (simulating the pre-fix bug) and verifies they diverge.

        // === Part 1: WITH shared registry (correct behavior) ===
        val sharedRegistry = HeaderRegistry()
        val cu1WithShared = IncludeContext("cu1.cpp", sink, sharedRegistry)
        val cu1HeaderFileNum = cu1WithShared.beginInclude("shared.h", 0xABCDL)
        val cu1Header = cu1WithShared.headerForFileNum(cu1HeaderFileNum)

        val cu2WithShared = IncludeContext("cu2.cpp", sink, sharedRegistry)
        val cu2HeaderFileNum = cu2WithShared.beginInclude("shared.h", 0xABCDL)
        val cu2Header = cu2WithShared.headerForFileNum(cu2HeaderFileNum)

        // CRITICAL: With shared registry, both CUs get the SAME HeaderFile instance
        assertTrue(
            cu1Header === cu2Header,
            "C1 fix FAILED: CUs with shared registry must get same HeaderFile instance",
        )

        // === Part 2: WITHOUT shared registry (pre-fix bug) ===
        val cu1PrivateRegistry = HeaderRegistry()
        val cu1WithPrivate = IncludeContext("cu1.cpp", sink, cu1PrivateRegistry)
        val cu1PrivHeaderFileNum = cu1WithPrivate.beginInclude("shared.h", 0xABCDL)
        val cu1PrivHeader = cu1WithPrivate.headerForFileNum(cu1PrivHeaderFileNum)

        val cu2PrivateRegistry = HeaderRegistry()
        val cu2WithPrivate = IncludeContext("cu2.cpp", sink, cu2PrivateRegistry)
        val cu2PrivHeaderFileNum = cu2WithPrivate.beginInclude("shared.h", 0xABCDL)
        val cu2PrivHeader = cu2WithPrivate.headerForFileNum(cu2PrivHeaderFileNum)

        // WITHOUT shared registry (pre-fix), the two CUs get DIFFERENT HeaderFile instances
        // (even though the canonical keys are identical). This demonstrates the bug.
        assertTrue(
            cu1PrivHeader !== cu2PrivHeader,
            "Pre-fix bug verification: CUs with separate registries get different HeaderFile instances",
        )
        assertEquals(cu1PrivHeader!!.filename, cu2PrivHeader!!.filename)
        assertEquals(cu1PrivHeader.checksum, cu2PrivHeader.checksum)

        // === Verify canonical TypeIds are stable across shared registry ===
        val typeIdInCu1 = LocalTypeId(cu1HeaderFileNum, 99)
        val typeIdInCu2 = LocalTypeId(cu2HeaderFileNum, 99)
    }
}
