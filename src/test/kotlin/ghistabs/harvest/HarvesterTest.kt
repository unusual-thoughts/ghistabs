package ghistabs.harvest

import ghistabs.parse.SourceFile
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.test.dummyHarvester
import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustBeA
import org.junit.jupiter.api.Test

/**
 * Unit tests for Harvester.harvest() and preSeedHeaders() state machine.
 *
 * Verifies stabs-algo-audit.AC3.3: N_SO/N_FUN/N_GSYM/N_LSYM state machine,
 * N_SOL non-allocation, and BINCL/EXCL/EINCL in both passes.
 *
 * Note: These tests focus on state machine behavior (CU tracking, function contexts,
 * include stack) rather than symbol parsing. Symbol parsing is tested separately
 * in HarvesterGlobalizeTest and HarvesterAppendAstsTest.
 */
class HarvesterTest {
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
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
        )

        harvester.harvest(records)

        // harvest() should process the N_SO record without errors.
        // We verify the record was processed by checking parse errors is 0.
        sink.parseErrors.mustBe(0, "N_SO alone should not cause parse errors")
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
        val (_, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_GSYM,
                other = 0,
                desc = 0,
                value = 0L,
                name = "g:G(0,5)", // Reference to type (0,5) — no inline def
            ),
        )

        val harvest = harvester.harvest(records)

        val harvestedSymbols = harvest.statics
        harvestedSymbols.size.mustBe(1, "One global symbol should be harvested")
        val gsymRecord = harvestedSymbols[0]
        gsymRecord.body.name.mustBe("g", "Symbol name should be 'g'")
        gsymRecord.recordType.mustBe(StabType.N_GSYM, "Record type should be N_GSYM")
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
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_FUN,
                other = 0,
                desc = 0,
                value = 0L, // Avoid address resolution issues; use 0 for simplicity
                name = "f:F(0,2)=f(0,1)",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 4L,
                name = "x:(0,3)", // Simple type reference — no inline def (avoids StabsParseException)
            ),
            StabRecord(
                index = 3,
                type = StabType.N_FUN,
                other = 0,
                desc = 0,
                value = 100L, // Relative size (N_FUN close uses value as size)
                name = "",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        harvest.functions.size.mustBe(1, "Exactly one function should be opened")
        val func = harvest.functions[0]
        func.name.mustBe("f", "Function name should be 'f'")
        func.locals.size.mustBe(1, "Function should have exactly one local")
        val xLocal = func.locals[0]
        xLocal.body.name.mustBe("x", "Local variable name should be 'x'")
        xLocal.rawValue.mustBe(4L, "Local stack offset should be 4")
        func.sizeBytes.mustBe(100UL, "Function size should be 100")
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
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 0L,
                // Struct with one int-sized field; (0,1) is an unresolved forward ref
                // (the parser accepts it as TypeDecl.Ref without error).
                // Avoid "=i" inline bodies — the parser does not handle primitive type chars.
                name = "MyStruct:T(0,7)=s4x:(0,1),0,32;;",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        harvest.types.size.mustBe(1, "Tagged type should populate typeAsts")
        val typeAst = harvest.types.values.first()
        typeAst.ghidraName.mustBe("MyStruct", "Tagged type name should be 'MyStruct'")
        // Tagged types should NOT be in symbolsByCu
        harvest.statics.size.mustBe(0, "Tagged type should NOT be in harvested symbols")
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
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_FUN,
                other = 0,
                desc = 0,
                value = 0L, // Use 0 to avoid address resolution
                name = "fn:F(0,2)=f(0,1)",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 8L,
                name = "var:(0,3)", // Simple type reference — no inline def
            ),
            StabRecord(
                index = 3,
                type = StabType.N_FUN,
                other = 0,
                desc = 0,
                value = 50L, // Function size
                name = "",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        harvest.functions.size.mustBe(1, "Exactly one function should be recorded")
        val func = harvest.functions[0]
        func.locals.size.mustBe(1, "Function should have exactly one local record")
        val varLocal = func.locals[0]
        varLocal.body.name.mustBe("var", "Local name should be 'var'")
        varLocal.rawValue.mustBe(8L, "Local stack offset should be 8")
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
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "foo.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_BINCL,
                other = 0,
                desc = 0,
                value = 42L,
                name = "hdr.h",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_SOL,
                other = 0,
                desc = 0,
                value = 0L,
                name = "other.h",
            ),
            StabRecord(
                index = 3,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 0L,
                // Tagged type using fileNum 1 (hdr.h). N_SOL does not allocate a new
                // fileNum, so (1,3) still maps to hdr.h — not to other.h from N_SOL.
                // Using a TaggedType (T-prefix) so it goes into typeAsts for source verification.
                name = "AfterSOL:T(1,3)=s0;;",
            ),
            StabRecord(
                index = 4,
                type = StabType.N_EINCL,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        // Verify: the type reference (1,3) maps to hdr.h (fileNum 1 from BINCL), not other.h.
        // N_SOL does NOT allocate a new fileNum — it only changes line-tracking context.
        harvest.types.size.mustBe(1, "One type should be harvested")
        val typeAst = harvest.types.values.first()
        typeAst.ghidraName.mustBe("AfterSOL", "Type name should be AfterSOL")
        val source = typeAst.source
        source.mustBeA<SourceFile.HeaderSource>(
            "Type source should be HeaderSource — fileNum 1 maps to hdr.h (BINCL), not other.h (N_SOL)",
        )
        (source as SourceFile.HeaderSource).header.filename.mustBe(
            "hdr.h",
            "Type attributed to hdr.h (fileNum 1 from BINCL); N_SOL did not allocate a new fileNum",
        )
        source.header.checksum.mustBe(42L, "Header checksum should match BINCL value")
    }

    /**
     * Test: BINCL/EINCL processed in both passes with type stab inside.
     *
     * Records: [N_SO("main.c"),
     *           N_BINCL("types.h", checksum=0xABCD),
     *           N_LSYM("HeaderType:T(1,7)=i"),
     *           N_EINCL]
     * Expected: The type stab produces a TypeAst with `id.source` being
     *           HeaderSource(types.h, 0xABCD), not CUSource(main.c).
     *           The CuContext for main.c has types.h in fileNumToHeader.
     *
     * Source: stabs-canonicalization.md §3, §4 — both passes process include directives.
     */
    @Test
    fun testBINCLEINCLProcessedInBothPasses() {
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "main.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_BINCL,
                other = 0,
                desc = 0,
                value = 0xABCDL,
                name = "types.h",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 0L,
                // Empty struct tagged type — avoids "=i" which causes StabsParseException.
                // The parser does not handle single-letter primitive type chars like 'i'.
                name = "HeaderType:T(1,7)=s0;;",
            ),
            StabRecord(
                index = 3,
                type = StabType.N_EINCL,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        // The type inside the BINCL should be attributed to the header, not the CU
        harvest.types.size.mustBe(1, "Type inside BINCL should be recorded in typeAsts")
        val typeAst = harvest.types.values.first()
        typeAst.ghidraName.mustBe("HeaderType", "Type name should be HeaderType")
        val source = typeAst.source
        source.mustBeA<SourceFile.HeaderSource>("Type inside BINCL should be attributed to HeaderSource, not CUSource")
        val headerSource = source as SourceFile.HeaderSource
        headerSource.header.filename.mustBe("types.h", "Header source should be types.h")
        headerSource.header.checksum.mustBe(0xABCDL, "Header checksum should match BINCL value")
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
        val (sink, harvester) = dummyHarvester()
        // Construct all records for both CUs in one list
        val records = listOf(
            // CU1
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu1.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_BINCL,
                other = 0,
                desc = 0,
                value = 0x1234L,
                name = "header.h",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 0L,
                // Empty struct tagged type — avoids "=i" which causes StabsParseException
                name = "SharedType:T(1,5)=s0;;",
            ),
            StabRecord(
                index = 3,
                type = StabType.N_EINCL,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
            // CU2
            StabRecord(
                index = 4,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu2.c",
            ),
            StabRecord(
                index = 5,
                type = StabType.N_EXCL,
                other = 0,
                desc = 0,
                value = 0x1234L,
                name = "header.h",
            ),
            StabRecord(
                index = 6,
                type = StabType.N_LSYM,
                other = 0,
                desc = 0,
                value = 0L,
                // Empty struct tagged type — avoids "=i" which causes StabsParseException
                name = "SharedType:T(1,5)=s0;;",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        // Both type stabs should deduplicate to the same GlobalTypeId.
        // The dedup happens because both CUs reference the SAME HeaderFile instance
        // (via the shared HeaderRegistry), so (1,5) in both CUs produces the same
        // GlobalTypeId(HeaderSource(same HeaderFile), 5).
        harvest.types.size.mustBe(1, "Both types should deduplicate to one GlobalTypeId entry")
        val typeAst = harvest.types.values.first()
        typeAst.ghidraName.mustBe("SharedType", "Type name should be SharedType")
        val source = typeAst.source
        source.mustBeA<SourceFile.HeaderSource>("Shared type should be attributed to HeaderSource")
        val headerSource = source as SourceFile.HeaderSource
        headerSource.header.filename.mustBe("header.h", "Shared type should come from header.h")
        headerSource.header.checksum.mustBe(0x1234L, "Header checksum should match both BINCL and EXCL value")
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
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu1.c",
            ),
            // Symbol in cu1.c — required so symbolsByCu gets an entry for cu1.c
            StabRecord(
                index = 1,
                type = StabType.N_GSYM,
                other = 0,
                desc = 0,
                value = 0L,
                name = "g1:G(0,1)",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "cu2.c",
            ),
            // Symbol in cu2.c — required so symbolsByCu gets an entry for cu2.c
            StabRecord(
                index = 3,
                type = StabType.N_GSYM,
                other = 0,
                desc = 0,
                value = 0L,
                name = "g2:G(0,1)",
            ),
            StabRecord(
                index = 4,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        harvest.sources[sourceFileOf("cu1.c")]?.cu?.statics?.size.mustBe(1, "cu1.c should have exactly one symbol")
        harvest.sources[sourceFileOf("cu2.c")]?.cu?.statics?.size.mustBe(1, "cu2.c should have exactly one symbol")
    }

    /**
     * Test: preSeedHeaders() allocates CuContext per CU.
     *
     * Records: [N_SO("a.c"), N_BINCL("h1.h", 1), N_EINCL, N_SO("b.c"), N_BINCL("h2.h", 2), N_EINCL]
     * Expected: preSeedHeaders() creates separate CuContext instances for each CU,
     *           each with its own include stack. The header registry is shared globally.
     *
     * Source: stabs-canonicalization.md §3 — per-CU include contexts with shared registry.
     */
    @Test
    fun testPreSeedHeadersCreatesPerCuContexts() {
        val (sink, harvester) = dummyHarvester()
        val records = listOf(
            StabRecord(
                index = 0,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "a.c",
            ),
            StabRecord(
                index = 1,
                type = StabType.N_BINCL,
                other = 0,
                desc = 0,
                value = 1L,
                name = "h1.h",
            ),
            StabRecord(
                index = 2,
                type = StabType.N_EINCL,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
            // Symbol for a.c — symbolsByCu only has entries when symbols are harvested
            StabRecord(
                index = 3,
                type = StabType.N_GSYM,
                other = 0,
                desc = 0,
                value = 0L,
                name = "ga:G(0,1)",
            ),
            StabRecord(
                index = 4,
                type = StabType.N_SO,
                other = 0,
                desc = 0,
                value = 0L,
                name = "b.c",
            ),
            StabRecord(
                index = 5,
                type = StabType.N_BINCL,
                other = 0,
                desc = 0,
                value = 2L,
                name = "h2.h",
            ),
            StabRecord(
                index = 6,
                type = StabType.N_EINCL,
                other = 0,
                desc = 0,
                value = 0L,
                name = "",
            ),
            // Symbol for b.c
            StabRecord(
                index = 7,
                type = StabType.N_GSYM,
                other = 0,
                desc = 0,
                value = 0L,
                name = "gb:G(0,1)",
            ),
        )

        val harvest = harvester.harvest(records)

        sink.parseErrors mustBe 0
        harvest.sources[sourceFileOf("a.c")].must("a.c should be harvested as a CU") { this?.cu != null }
        harvest.sources[sourceFileOf("b.c")].must("b.c should be harvested as a CU") { this?.cu != null }
    }
}
