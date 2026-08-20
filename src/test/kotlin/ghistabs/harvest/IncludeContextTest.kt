package ghistabs.harvest

import ghistabs.diagnose.CapturingSink
import ghistabs.parse.LocalTypeId
import ghistabs.parse.SourceFile
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
        val ctx = IncludeContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)
        val fileNum = ctx.beginInclude("header.h", 0x123L)
        assertEquals(1, fileNum)
        val header = ctx.headerForFileNum(fileNum)
        assertNotNull(header)
        assertEquals("header.h", header!!.filename)
        assertEquals(0x123L, header.checksum)
    }

    @Test
    fun `endInclude pops stack without changing fileNum`() {
        val ctx = IncludeContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)
        val fileNum = ctx.beginInclude("header.h", 0x123L)
        ctx.endInclude()
        // After popping, headerForFileNum should still return the header (it was registered by fileNum)
        assertNotNull(ctx.headerForFileNum(fileNum))
    }

    @Test
    fun `two CUs with same BINCL get same HeaderFile instance`() {
        val ctx1 = IncludeContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = registry)
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = IncludeContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = registry)
        val fileNum2 = ctx2.beginInclude("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance (object identity)
        assertTrue(header1 === header2)
        assertEquals("header.h", header1!!.filename)
        assertEquals(0x123L, header1.checksum)
    }

    @Test
    fun `remount with prior BINCL reuses same HeaderFile`() {
        val ctx1 = IncludeContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = registry)
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = IncludeContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = registry)
        val fileNum2 = ctx2.remount("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance
        assertTrue(header1 === header2)
        // same local id
        assertTrue(fileNum1 == 1)
        assertTrue(fileNum2 == 1)
    }

    @Test
    fun `forward EXCL without prior BINCL allocates placeholder and logs`() {
        val ctx = IncludeContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)
        val fileNum2 = ctx.remount("unknown.h", 0x456L)
        val header = ctx.headerForFileNum(fileNum2)

        assertNotNull(header)
        assertEquals("unknown.h", header!!.filename)
        assertEquals(0x456L, header.checksum)
        assertNull(header.originatingCu)

        // Check log was emitted
        val forwardExclLog = sink.lines.find { it.tag == "forward-excl" }
        assertNotNull(forwardExclLog)
        assertTrue(forwardExclLog!!.msg!!.contains("unknown.h"))
        assertTrue(forwardExclLog.msg.contains("0x456"))
    }

    @Test
    fun `forward EXCL then BINCL share the same HeaderFile instance (D1 fixed)`() {
        val ctx1 = IncludeContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = registry)
        val fileNum1Excl = ctx1.remount("header.h", 0x123L)
        val header1Excl = ctx1.headerForFileNum(fileNum1Excl)

        // Verify forward-excl log was emitted exactly once
        assertEquals(1, sink.lines.filter { it.tag == "forward-excl" }.size)
        assertNull(header1Excl!!.originatingCu)

        // A later CU with real BINCL must reuse the placeholder, so types attributed
        // to (filename, checksum) from either CU land at the same GlobalTypeId.
        val ctx2 = IncludeContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = registry)
        val fileNum2Bincl = ctx2.beginInclude("header.h", 0x123L)
        val header2Bincl = ctx2.headerForFileNum(fileNum2Bincl)

        assertTrue(header1Excl === header2Bincl)
    }

    @Test
    fun `endInclude with empty stack logs unbalanced warning`() {
        val ctx = IncludeContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)

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
        val cu1WithShared = IncludeContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = sharedRegistry)
        val cu1HeaderFileNum = cu1WithShared.beginInclude("shared.h", 0xABCDL)
        val cu1Header = cu1WithShared.headerForFileNum(cu1HeaderFileNum)

        val cu2WithShared = IncludeContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = sharedRegistry)
        val cu2HeaderFileNum = cu2WithShared.beginInclude("shared.h", 0xABCDL)
        val cu2Header = cu2WithShared.headerForFileNum(cu2HeaderFileNum)

        // CRITICAL: With shared registry, both CUs get the SAME HeaderFile instance
        assertTrue(
            cu1Header === cu2Header,
            "C1 fix FAILED: CUs with shared registry must get same HeaderFile instance",
        )

        // === Part 2: WITHOUT shared registry (pre-fix bug) ===
        val cu1PrivateRegistry = HeaderRegistry()
        val cu1WithPrivate = IncludeContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = cu1PrivateRegistry)
        val cu1PrivHeaderFileNum = cu1WithPrivate.beginInclude("shared.h", 0xABCDL)
        val cu1PrivHeader = cu1WithPrivate.headerForFileNum(cu1PrivHeaderFileNum)

        val cu2PrivateRegistry = HeaderRegistry()
        val cu2WithPrivate = IncludeContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = cu2PrivateRegistry)
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

        // === Verify cross-CU sourceFor resolves to the same SourceFile for same (filename, checksum) ===
        val typeIdInCu1 = LocalTypeId(cu1HeaderFileNum, 99)
        val typeIdInCu2 = LocalTypeId(cu2HeaderFileNum, 99)
        assertEquals(
            cu1WithShared.sourceFor(typeIdInCu1),
            cu2WithShared.sourceFor(typeIdInCu2),
            "C1 fix: sourceFor for same (filename, checksum) must yield equal SourceFile across CUs",
        )
    }

    @Test
    fun `BINCL re-entry for same header produces same HeaderFile instance`() {
        val registry = HeaderRegistry()
        val ctx = IncludeContext(SourceFile.CUSource("test.c"), sink = sink, registry = registry)

        val fn1 = ctx.beginInclude("hdr.h", 0xABCD)
        ctx.endInclude()
        val fn2 = ctx.beginInclude("hdr.h", 0xABCD)
        ctx.endInclude()

        // Two fileNums were allocated
        assertTrue(fn1 != fn2, "Re-entry should allocate two distinct fileNums")

        // Both map to the same HeaderFile instance
        val h1 = ctx.headerForFileNum(fn1)
        val h2 = ctx.headerForFileNum(fn2)
        assertNotNull(h1)
        assertNotNull(h2)
        assertTrue(h1 === h2, "Same (filename, checksum) should resolve to same HeaderFile instance")

        // Types via either fileNum produce the same GlobalTypeId
        val id1 = ctx.sourceFor(LocalTypeId(fn1, 7))
        val id2 = ctx.sourceFor(LocalTypeId(fn2, 7))
        assertEquals(id1, id2, "Same fileNum type should produce equal GlobalTypeId")
    }
}
