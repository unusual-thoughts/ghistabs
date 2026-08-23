package ghistabs.harvest

import ghistabs.diagnose.CapturingSink
import ghistabs.parse.LocalTypeId
import ghistabs.parse.SourceFile
import ghistabs.test.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class CuContextTest {
    private lateinit var registry: HeaderRegistry
    private lateinit var sink: CapturingSink

    @BeforeEach
    fun setUp() {
        sink = CapturingSink()
        registry = HeaderRegistry(sink)
    }

    @Test
    fun `beginInclude allocates fileNum and pushes stack`() {
        val ctx = CuContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)
        val fileNum = ctx.beginInclude("header.h", 0x123L)
        fileNum mustBe 1
        val header = ctx.headerForFileNum(fileNum)
        header mustNotBe null
        header!!.filename mustBe "header.h"
        header.checksum mustBe 0x123L
    }

    @Test
    fun `endInclude pops stack without changing fileNum`() {
        val ctx = CuContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)
        val fileNum = ctx.beginInclude("header.h", 0x123L)
        ctx.endInclude()
        // After popping, headerForFileNum should still return the header (it was registered by fileNum)
        ctx.headerForFileNum(fileNum) mustNotBe null
    }

    @Test
    fun `two CUs with same BINCL get same HeaderFile instance`() {
        val ctx1 = CuContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = registry)
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = CuContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = registry)
        val fileNum2 = ctx2.beginInclude("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance (object identity)
        header1 mustBeSameAs header2
        header1!!.filename mustBe "header.h"
        header1.checksum mustBe 0x123L
    }

    @Test
    fun `remount with prior BINCL reuses same HeaderFile`() {
        val ctx1 = CuContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = registry)
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = CuContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = registry)
        val fileNum2 = ctx2.remount("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance
        header1 mustBeSameAs header2
        // same local id
        fileNum1 mustBe 1
        fileNum2 mustBe 1
    }

    @Test
    fun `forward EXCL without prior BINCL allocates placeholder and logs`() {
        val ctx = CuContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)
        val fileNum2 = ctx.remount("unknown.h", 0x456L)
        val header = ctx.headerForFileNum(fileNum2)

        header mustNotBe null
        header!!.filename mustBe "unknown.h"
        header.checksum mustBe 0x456L
        header.originatingCu mustBe null

        // Check log was emitted
        val forwardExclLog = sink.lines.find { it.tag == "forward-excl" }
        forwardExclLog mustNotBe null
        "unknown.h" mustBeIn forwardExclLog!!.msg!!
        "0x456" mustBeIn forwardExclLog.msg
    }

    @Test
    fun `forward EXCL then BINCL share the same HeaderFile instance (D1 fixed)`() {
        val ctx1 = CuContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = registry)
        val fileNum1Excl = ctx1.remount("header.h", 0x123L)
        val header1Excl = ctx1.headerForFileNum(fileNum1Excl)

        // Verify forward-excl log was emitted exactly once
        sink.lines.filter { it.tag == "forward-excl" }.size mustBe 1
        header1Excl!!.originatingCu mustBe null

        // A later CU with real BINCL must reuse the placeholder, so types attributed
        // to (filename, checksum) from either CU land at the same GlobalTypeId.
        val ctx2 = CuContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = registry)
        val fileNum2Bincl = ctx2.beginInclude("header.h", 0x123L)
        val header2Bincl = ctx2.headerForFileNum(fileNum2Bincl)

        header1Excl mustBeSameAs header2Bincl
    }

    @Test
    fun `endInclude with empty stack logs unbalanced warning`() {
        val ctx = CuContext(SourceFile.CUSource("test.cpp"), sink = sink, registry = registry)

        // Call endInclude on empty stack
        ctx.endInclude()

        // Check log was emitted
        val unbalancedLog = sink.lines.find { it.tag == "einc-unbalanced" }
        unbalancedLog mustNotBe null
        "empty stack" mustBeIn unbalancedLog!!.msg!!
    }

    @Test
    fun `regression C1 shared HeaderRegistry ensures cross-CU dedup`() {
        // This test verifies the critical C1 fix: when multiple CUs share the same
        // registry, they must get the SAME HeaderFile instance for the same (filename, checksum).
        // Without the fix, each CU instantiates its own CuContext with CuContext(name, sink)
        // using the default HeaderRegistry(), creating isolated registries and breaking dedup.
        //
        // This test constructs two CUs with EXPLICIT shared registry (simulating the fixed production code)
        // and verifies identity. Then it separately constructs two CUs with SEPARATE registries
        // (simulating the pre-fix bug) and verifies they diverge.

        // === Part 1: WITH shared registry (correct behavior) ===
        val sharedRegistry = HeaderRegistry()
        val cu1WithShared = CuContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = sharedRegistry)
        val cu1HeaderFileNum = cu1WithShared.beginInclude("shared.h", 0xABCDL)
        val cu1Header = cu1WithShared.headerForFileNum(cu1HeaderFileNum)

        val cu2WithShared = CuContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = sharedRegistry)
        val cu2HeaderFileNum = cu2WithShared.beginInclude("shared.h", 0xABCDL)
        val cu2Header = cu2WithShared.headerForFileNum(cu2HeaderFileNum)

        // CRITICAL: With shared registry, both CUs get the SAME HeaderFile instance

        cu1Header.mustBeSameAs(
            cu2Header,
            "C1 fix FAILED: CUs with shared registry must get same HeaderFile instance",
        )

        // === Part 2: WITHOUT shared registry (pre-fix bug) ===
        val cu1PrivateRegistry = HeaderRegistry()
        val cu1WithPrivate = CuContext(SourceFile.CUSource("cu1.cpp"), sink = sink, registry = cu1PrivateRegistry)
        val cu1PrivHeaderFileNum = cu1WithPrivate.beginInclude("shared.h", 0xABCDL)
        val cu1PrivHeader = cu1WithPrivate.headerForFileNum(cu1PrivHeaderFileNum)

        val cu2PrivateRegistry = HeaderRegistry()
        val cu2WithPrivate = CuContext(SourceFile.CUSource("cu2.cpp"), sink = sink, registry = cu2PrivateRegistry)
        val cu2PrivHeaderFileNum = cu2WithPrivate.beginInclude("shared.h", 0xABCDL)
        val cu2PrivHeader = cu2WithPrivate.headerForFileNum(cu2PrivHeaderFileNum)

        // WITHOUT shared registry (pre-fix), the two CUs get DIFFERENT HeaderFile instances
        // (even though the canonical keys are identical). This demonstrates the bug.
        cu1PrivHeader.mustNotBeSameAs(
            cu2PrivHeader,
            "Pre-fix bug verification: CUs with separate registries get different HeaderFile instances",
        )
        cu2PrivHeader!!.filename mustBe cu1PrivHeader!!.filename
        cu2PrivHeader.checksum mustBe cu1PrivHeader.checksum

        // === Verify cross-CU sourceFor resolves to the same SourceFile for same (filename, checksum) ===
        val typeIdInCu1 = LocalTypeId(cu1HeaderFileNum, 99)
        val typeIdInCu2 = LocalTypeId(cu2HeaderFileNum, 99)
        cu2WithShared.sourceFor(typeIdInCu2).mustBe(
            cu1WithShared.sourceFor(typeIdInCu1),
            "C1 fix: sourceFor for same (filename, checksum) must yield equal SourceFile across CUs",
        )
    }

    @Test
    fun `BINCL re-entry for same header produces same HeaderFile instance`() {
        val registry = HeaderRegistry()
        val ctx = CuContext(SourceFile.CUSource("test.c"), sink = sink, registry = registry)

        val fn1 = ctx.beginInclude("hdr.h", 0xABCD)
        ctx.endInclude()
        val fn2 = ctx.beginInclude("hdr.h", 0xABCD)
        ctx.endInclude()

        // Two fileNums were allocated
        fn1.mustNotBe(fn2, "Re-entry should allocate two distinct fileNums")

        // Both map to the same HeaderFile instance
        val h1 = ctx.headerForFileNum(fn1)
        val h2 = ctx.headerForFileNum(fn2)
        h1 mustNotBe null
        h2 mustNotBe null
        h1.mustBeSameAs(h2, "Same (filename, checksum) should resolve to same HeaderFile instance")

        // Types via either fileNum produce the same GlobalTypeId
        val id1 = ctx.sourceFor(LocalTypeId(fn1, 7))
        val id2 = ctx.sourceFor(LocalTypeId(fn2, 7))
        id2.mustBe(id1, "Same fileNum type should produce equal GlobalTypeId")
    }
}
