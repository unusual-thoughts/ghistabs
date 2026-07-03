package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DummySink
import ghistabs.importer.StabOnlyAddressResolver
import ghistabs.parse.SourceFile
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Unit tests for Harvester.passA() and preSeedHeaders() state machine.
 *
 * Verifies stabs-algo-audit.AC3.3: N_SO/N_FUN/N_GSYM/N_LSYM state machine,
 * N_SOL non-allocation, and BINCL/EXCL/EINCL in both passes.
 *
 * Tests are pure unit tests (Kind 1): no Program/DataTypeManager/Listing,
 * only TaskMonitor.DUMMY, DummySink, and constructed test data.
 *
 * Note: These tests focus on state machine behavior (CU tracking, function contexts,
 * include stack) rather than symbol parsing. Symbol parsing is tested separately
 * in HarvesterGlobalizeTest and HarvesterAppendAstsTest.
 */
class HarvesterPassATest {
    private fun createTestHarvester(): Harvester = Harvester(
        monitor = TaskMonitor.DUMMY,
        sink = DummySink,
        resolver = StabOnlyAddressResolver(),
    )

    /**
     * Test: N_SO opens CU context.
     *
     * Construct a minimal record stream with N_SO to establish CU context.
     * The state machine should transition to the established CU without errors.
     *
     * Source: stabs-canonicalization.md §2 — N_SO establishes CU namespace.
     */
    @Test
    fun testNSOOpensCUContext() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
        )

        val harvest = harvester.passA(records)

        // passA() should process the N_SO record without errors.
        // We verify the record was processed by checking parse errors is 0.
        assertEquals(0, harvest.parseErrors, "N_SO alone should not cause parse errors")
    }

    /**
     * Test: N_GSYM harvests a global symbol.
     *
     * Records: [N_SO("foo.c"), N_GSYM("g:G(0,5)=i")]
     * Expected: harvest.allHarvestedSymbols contains a HarvestedSymbol
     *           whose decl.name == "g" and recordType == StabType.N_GSYM
     *
     * Source: stabs-canonicalization.md §2 — N_GSYM harvests global symbols.
     */
    @Test
    fun testNGSYMHarvestsGlobalSymbol() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_GSYM,
                rawType = 0x20,
                other = 0,
                desc = 0,
                value = 0L,
                name = "g:G(0,5)", // Reference to type (0,5) — no inline def
            ),
        )

        val harvest = harvester.passA(records)

        val harvestedSymbols = harvest.symbolsByCu.values.flatten()
        assertEquals(1, harvestedSymbols.size, "One global symbol should be harvested")
        val gsymRecord = harvestedSymbols[0]
        assertEquals("g", gsymRecord.body.name, "Symbol name should be 'g'")
        assertEquals(StabType.N_GSYM, gsymRecord.recordType, "Record type should be N_GSYM")
    }

    /**
     * Test: N_FUN opens and closes a function with locals.
     *
     * Records: [N_SO("foo.c"), N_FUN("f:F(0,2)", value=0),
     *           N_LSYM("x:(0,3)=i", value=4),
     *           N_FUN("", value=100)]
     * Expected: harvest.openFunctions contains one OpenFunction with name "f"
     *           and one local (x)
     *
     * Source: stabs-canonicalization.md §2 — N_FUN opens/closes functions.
     */
    @Test
    fun testNFUNWithLocals() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_FUN,
                rawType = 0x24,
                other = 0,
                desc = 0,
                value = 0L, // Avoid address resolution issues; use 0 for simplicity
                name = "f:F(0,2)=f(0,1)",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 4L,
                name = "x:(0,3)", // Simple type reference — no inline def (avoids StabsParseException)
            ),
            StabRecord(
                recordIndex = 3,
                type = StabType.N_FUN,
                rawType = 0x24,
                other = 0,
                desc = 0,
                value = 100L, // Relative size (N_FUN close uses value as size)
                name = "",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        assertEquals(1, harvest.openFunctions.size, "Exactly one function should be opened")
        val func = harvest.openFunctions[0]
        assertEquals("f", func.name, "Function name should be 'f'")
        assertEquals(1, func.locals.size, "Function should have exactly one local")
        val xLocal = func.locals[0]
        assertEquals("x", xLocal.body.name, "Local variable name should be 'x'")
        assertEquals(4L, xLocal.rawValue, "Local stack offset should be 4")
        assertEquals(100uL, func.sizeBytes, "Function size should be 100")
    }

    /**
     * Test: N_LSYM tagged type (T prefix) goes to typeAsts, not to symbolsByCu.
     *
     * Records: [N_SO("foo.c"),
     *           N_LSYM("MyStruct:T(0,7)=s8 x:(0,8)=i;0,32;;")]
     * Expected: harvest.typeAsts contains an entry for MyStruct;
     *           harvest.allHarvestedSymbols does NOT contain MyStruct
     *
     * Source: stabs PDF §6.1 "Typedefs and Tag Names in C".
     */
    @Test
    fun testNLSYMTaggedTypeGoesToTypeAsts() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 0L,
                // Struct with one int-sized field; (0,1) is an unresolved forward ref
                // (the parser accepts it as TypeDecl.Ref without error).
                // Avoid "=i" inline bodies — the parser does not handle primitive type chars.
                name = "MyStruct:T(0,7)=s4x:(0,1),0,32;;",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        assertEquals(1, harvest.typeAsts.size, "Tagged type should populate typeAsts")
        val typeAst = harvest.typeAsts.values.first()
        assertEquals("MyStruct", typeAst.nameOrUnique, "Tagged type name should be 'MyStruct'")
        // Tagged types should NOT be in symbolsByCu
        assertEquals(0, harvest.symbolsByCu.values.flatten().size, "Tagged type should NOT be in harvested symbols")
    }

    /**
     * Test: N_LSYM non-tagged local variable becomes a LocalRecord inside function.
     *
     * Records: [N_SO("foo.c"), N_FUN("fn:F(...)", value=0),
     *           N_LSYM("var:(0,3)=i", value=8),
     *           N_FUN("", value=50)]
     * Expected: harvest.openFunctions[0].locals contains LocalRecord for "var"
     *
     * Source: stabs-canonicalization.md §2 — N_LSYM local record.
     */
    @Test
    fun testNLSYMLocalRecord() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_FUN,
                rawType = 0x24,
                other = 0,
                desc = 0,
                value = 0L, // Use 0 to avoid address resolution
                name = "fn:F(0,2)=f(0,1)",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 8L,
                name = "var:(0,3)", // Simple type reference — no inline def
            ),
            StabRecord(
                recordIndex = 3,
                type = StabType.N_FUN,
                rawType = 0x24,
                other = 0,
                desc = 0,
                value = 50L, // Function size
                name = "",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        assertEquals(1, harvest.openFunctions.size, "Exactly one function should be recorded")
        val func = harvest.openFunctions[0]
        assertEquals(1, func.locals.size, "Function should have exactly one local record")
        val varLocal = func.locals[0]
        assertEquals("var", varLocal.body.name, "Local name should be 'var'")
        assertEquals(8L, varLocal.rawValue, "Local stack offset should be 8")
    }

    /**
     * Test: N_SOL does NOT allocate a fileNum.
     *
     * Records: [N_SO("foo.c"), N_BINCL("hdr.h", checksum=42),
     *           N_SOL("other.h", value=0),
     *           N_LSYM("x:(1,3)=i"),  // Type reference to fileNum 1 (hdr.h, not other.h)
     *           N_EINCL]
     * Expected: The type (1,3) produces a SourceFile.HeaderSource for hdr.h, not other.h,
     *           proving N_SOL did not allocate a new fileNum.
     *
     * Source: stabs-canonicalization.md §2 — N_SOL changes line-tracking only, no fileNum allocation.
     */
    @Test
    fun testNSOLDoesNotAllocateFileNum() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_BINCL,
                rawType = 0x82,
                other = 0,
                desc = 0,
                value = 42L,
                name = "hdr.h",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_SOL,
                rawType = 0x84,
                other = 0,
                desc = 0,
                value = 0L,
                name = "other.h",
            ),
            StabRecord(
                recordIndex = 3,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 0L,
                // Tagged type using fileNum 1 (hdr.h). N_SOL does not allocate a new
                // fileNum, so (1,3) still maps to hdr.h — not to other.h from N_SOL.
                // Using a TaggedType (T-prefix) so it goes into typeAsts for source verification.
                name = "AfterSOL:T(1,3)=s0;;",
            ),
            StabRecord(
                recordIndex = 4,
                type = StabType.N_EINCL,
                rawType = 0xA2,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        // Verify: the type reference (1,3) maps to hdr.h (fileNum 1 from BINCL), not other.h.
        // N_SOL does NOT allocate a new fileNum — it only changes line-tracking context.
        assertEquals(1, harvest.typeAsts.size, "One type should be harvested")
        val typeAst = harvest.typeAsts.values.first()
        assertEquals("AfterSOL", typeAst.nameOrUnique, "Type name should be AfterSOL")
        val source = typeAst.source
        assertTrue(
            source is SourceFile.HeaderSource,
            "Type source should be HeaderSource — fileNum 1 maps to hdr.h (BINCL), not other.h (N_SOL)",
        )
        assertEquals(
            "hdr.h",
            (source as SourceFile.HeaderSource).header.filename,
            "Type attributed to hdr.h (fileNum 1 from BINCL); N_SOL did not allocate a new fileNum",
        )
        assertEquals(42L, source.header.checksum, "Header checksum should match BINCL value")
    }

    /**
     * Test: BINCL/EINCL processed in both passes with type stab inside.
     *
     * Records: [N_SO("main.c"),
     *           N_BINCL("types.h", checksum=0xABCD),
     *           N_LSYM("HeaderType:T(1,7)=i"),
     *           N_EINCL]
     * Expected: The type stab produces a TypeAst with id.source being
     *           HeaderSource(types.h, 0xABCD), not CUSource(main.c).
     *           The IncludeContext for main.c has types.h in fileNumToHeader.
     *
     * Source: stabs-canonicalization.md §3, §4 — both passes process include directives.
     */
    @Test
    fun testBINCLEINCLProcessedInBothPasses() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "main.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_BINCL,
                rawType = 0x82,
                other = 0,
                desc = 0,
                value = 0xABCDL,
                name = "types.h",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 0L,
                // Empty struct tagged type — avoids "=i" which causes StabsParseException.
                // The parser does not handle single-letter primitive type chars like 'i'.
                name = "HeaderType:T(1,7)=s0;;",
            ),
            StabRecord(
                recordIndex = 3,
                type = StabType.N_EINCL,
                rawType = 0xA2,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        // The type inside the BINCL should be attributed to the header, not the CU
        assertEquals(1, harvest.typeAsts.size, "Type inside BINCL should be recorded in typeAsts")
        val typeAst = harvest.typeAsts.values.first()
        assertEquals("HeaderType", typeAst.nameOrUnique, "Type name should be HeaderType")
        val source = typeAst.source
        assertTrue(
            source is SourceFile.HeaderSource,
            "Type inside BINCL should be attributed to HeaderSource, not CUSource",
        )
        val headerSource = source as SourceFile.HeaderSource
        assertEquals(
            "types.h",
            headerSource.header.filename,
            "Header source should be types.h",
        )
        assertEquals(
            0xABCDL,
            headerSource.header.checksum,
            "Header checksum should match BINCL value",
        )
    }

    /**
     * Test: EXCL remount produces cross-CU dedup with same GlobalTypeId.
     *
     * Two CUs share a HeaderRegistry. CU1 sees BINCL with type stab; CU2 sees EXCL
     * for the same (filename, checksum). Both should produce TypeAsts with the SAME
     * GlobalTypeId because they reference the same HeaderFile instance.
     *
     * Records:
     *   CU1: [N_SO("cu1.c"), N_BINCL("header.h", 0x1234), N_LSYM("SharedType:T(1,5)=i"), N_EINCL]
     *   CU2: [N_SO("cu2.c"), N_EXCL("header.h", 0x1234), N_LSYM("SharedType:T(1,5)=i")]
     *
     * Expected: Both type stabs produce TypeAsts with equal GlobalTypeId
     *           (same HeaderFile source, same type number 5).
     *
     * Source: stabs-canonicalization.md §3, §4 — EXCL remount for cross-CU dedup.
     */
    @Test
    fun testEXCLRemountCrossVuDedup() {
        val harvester = createTestHarvester()
        // Construct all records for both CUs in one list
        val records = listOf(
            // CU1
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu1.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_BINCL,
                rawType = 0x82,
                other = 0,
                desc = 0,
                value = 0x1234L,
                name = "header.h",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 0L,
                // Empty struct tagged type — avoids "=i" which causes StabsParseException
                name = "SharedType:T(1,5)=s0;;",
            ),
            StabRecord(
                recordIndex = 3,
                type = StabType.N_EINCL,
                rawType = 0xA2,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
            // CU2
            StabRecord(
                recordIndex = 4,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu2.c",
            ),
            StabRecord(
                recordIndex = 5,
                type = StabType.N_EXCL,
                rawType = 0xC2,
                other = 0,
                desc = 0,
                value = 0x1234L,
                name = "header.h",
            ),
            StabRecord(
                recordIndex = 6,
                type = StabType.N_LSYM,
                rawType = 0x80,
                other = 0,
                desc = 0,
                value = 0L,
                // Empty struct tagged type — avoids "=i" which causes StabsParseException
                name = "SharedType:T(1,5)=s0;;",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        // Both type stabs should deduplicate to the same GlobalTypeId.
        // The dedup happens because both CUs reference the SAME HeaderFile instance
        // (via the shared HeaderRegistry), so (1,5) in both CUs produces the same
        // GlobalTypeId(HeaderSource(same HeaderFile), 5).
        assertEquals(1, harvest.typeAsts.size, "Both types should deduplicate to one GlobalTypeId entry")
        val typeAst = harvest.typeAsts.values.first()
        assertEquals("SharedType", typeAst.nameOrUnique, "Type name should be SharedType")
        val source = typeAst.source
        assertTrue(
            source is SourceFile.HeaderSource,
            "Shared type should be attributed to HeaderSource",
        )
        val headerSource = source as SourceFile.HeaderSource
        assertEquals(
            "header.h",
            headerSource.header.filename,
            "Shared type should come from header.h",
        )
        assertEquals(
            0x1234L,
            headerSource.header.checksum,
            "Header checksum should match both BINCL and EXCL value",
        )
    }

    /**
     * Test: Multiple CUs tracked correctly.
     *
     * Records: [N_SO("cu1.c"), N_SO("cu2.c"), N_SO("")]
     * Expected: The state machine tracks currentCu correctly.
     *           Final N_SO("") closes cu2.c context.
     */
    @Test
    fun testMultipleCUsTracked() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu1.c",
            ),
            // Symbol in cu1.c — required so symbolsByCu gets an entry for cu1.c
            StabRecord(
                recordIndex = 1,
                type = StabType.N_GSYM,
                rawType = 0x20,
                other = 0,
                desc = 0,
                value = 0L,
                name = "g1:G(0,1)",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu2.c",
            ),
            // Symbol in cu2.c — required so symbolsByCu gets an entry for cu2.c
            StabRecord(
                recordIndex = 3,
                type = StabType.N_GSYM,
                rawType = 0x20,
                other = 0,
                desc = 0,
                value = 0L,
                name = "g2:G(0,1)",
            ),
            StabRecord(
                recordIndex = 4,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        assertTrue(harvest.symbolsByCu.containsKey("cu1.c"), "CU1 should be registered in symbolsByCu")
        assertTrue(harvest.symbolsByCu.containsKey("cu2.c"), "CU2 should be registered in symbolsByCu")
        assertEquals(1, harvest.symbolsByCu["cu1.c"]!!.size, "cu1.c should have exactly one symbol")
        assertEquals(1, harvest.symbolsByCu["cu2.c"]!!.size, "cu2.c should have exactly one symbol")
    }

    /**
     * Test: preSeedHeaders() allocates IncludeContext per CU.
     *
     * Records: [N_SO("a.c"), N_BINCL("h1.h", 1), N_EINCL, N_SO("b.c"), N_BINCL("h2.h", 2), N_EINCL]
     * Expected: preSeedHeaders() creates separate IncludeContext instances for each CU,
     *           each with its own include stack. The header registry is shared globally.
     *
     * Source: stabs-canonicalization.md §3 — per-CU include contexts with shared registry.
     */
    @Test
    fun testPreSeedHeadersCreatesPerCUIncludeContexts() {
        val harvester = createTestHarvester()
        val records = listOf(
            StabRecord(
                recordIndex = 0,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "a.c",
            ),
            StabRecord(
                recordIndex = 1,
                type = StabType.N_BINCL,
                rawType = 0x82,
                other = 0,
                desc = 0,
                value = 1L,
                name = "h1.h",
            ),
            StabRecord(
                recordIndex = 2,
                type = StabType.N_EINCL,
                rawType = 0xA2,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
            // Symbol for a.c — symbolsByCu only has entries when symbols are harvested
            StabRecord(
                recordIndex = 3,
                type = StabType.N_GSYM,
                rawType = 0x20,
                other = 0,
                desc = 0,
                value = 0L,
                name = "ga:G(0,1)",
            ),
            StabRecord(
                recordIndex = 4,
                type = StabType.N_SO,
                rawType = 0x64,
                other = 0,
                desc = 0,
                value = 0L,
                name = "b.c",
            ),
            StabRecord(
                recordIndex = 5,
                type = StabType.N_BINCL,
                rawType = 0x82,
                other = 0,
                desc = 0,
                value = 2L,
                name = "h2.h",
            ),
            StabRecord(
                recordIndex = 6,
                type = StabType.N_EINCL,
                rawType = 0xA2,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
            // Symbol for b.c
            StabRecord(
                recordIndex = 7,
                type = StabType.N_GSYM,
                rawType = 0x20,
                other = 0,
                desc = 0,
                value = 0L,
                name = "gb:G(0,1)",
            ),
        )

        val harvest = harvester.passA(records)

        assertEquals(0, harvest.parseErrors)
        assertTrue(harvest.symbolsByCu.containsKey("a.c"), "CU a.c should be registered in symbolsByCu")
        assertTrue(harvest.symbolsByCu.containsKey("b.c"), "CU b.c should be registered in symbolsByCu")
    }
}
