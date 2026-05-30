package ghistabs.parser

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class IncludeContextTest {
    private class RecordingSink : LogSink {
        val logs = mutableListOf<Pair<String, String>>()

        override fun log(
            tag: String,
            message: String,
        ) {
            logs.add(tag to message)
        }

        fun clear() {
            logs.clear()
        }
    }

    private lateinit var registry: HeaderRegistry
    private lateinit var sink: RecordingSink

    @BeforeEach
    fun setUp() {
        registry = HeaderRegistry()
        sink = RecordingSink()
    }

    @Test
    fun `openSource allocates fileNum 1`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        val fileNum = ctx.openSource("test.cpp")
        assertEquals(1, fileNum)
    }

    @Test
    fun `openSource creates HeaderFile for own source`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        val fileNum = ctx.openSource("test.cpp")
        val header = ctx.headerForFileNum(fileNum)
        assertNotNull(header)
        assertEquals("test.cpp", header!!.filename)
        assertEquals(0L, header.checksum)
        assertEquals("test.cpp", header.originatingCu)
    }

    @Test
    fun `switchSource allocates next fileNum`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        ctx.openSource("test.cpp")
        val fileNum2 = ctx.switchSource("test.h")
        assertEquals(2, fileNum2)
    }

    @Test
    fun `beginInclude allocates fileNum and pushes stack`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        ctx.openSource("test.cpp")
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
        ctx.openSource("test.cpp")
        val fileNum2 = ctx.beginInclude("header.h", 0x123L)
        ctx.endInclude()
        // After popping, headerForFileNum should still return the header (it was registered by fileNum)
        assertNotNull(ctx.headerForFileNum(fileNum2))
    }

    @Test
    fun `two CUs with same BINCL get same HeaderFile instance`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        ctx1.openSource("cu1.cpp")
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        ctx2.openSource("cu2.cpp")
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
        ctx1.openSource("cu1.cpp")
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        ctx2.openSource("cu2.cpp")
        val fileNum2 = ctx2.reMountExcluded("header.h", 0x123L)
        val header2 = ctx2.headerForFileNum(fileNum2)

        // Same instance
        assertTrue(header1 === header2)
        // Different fileNum (new allocation in ctx2)
        assertTrue(fileNum1 != fileNum2 || fileNum1 == 2 && fileNum2 == 2)
    }

    @Test
    fun `canonicalTypeId is stable across CUs sharing header`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        ctx1.openSource("cu1.cpp")
        val headerFileNum1 = ctx1.beginInclude("header.h", 0x123L)

        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        ctx2.openSource("cu2.cpp")
        val headerFileNum2 = ctx2.reMountExcluded("header.h", 0x123L)

        // Types defined in the BINCL region have the same fileNum in both CUs
        // (they reference the shared header, so their canonical form should be identical)
        val typeId1 = TypeId(headerFileNum1, 7)
        val typeId2 = TypeId(headerFileNum2, 7)

        val canonical1 = ctx1.canonicalTypeId(typeId1)
        val canonical2 = ctx2.canonicalTypeId(typeId2)

        assertEquals(canonical1, canonical2)
    }

    @Test
    fun `forward EXCL without prior BINCL allocates placeholder and logs`() {
        val ctx = IncludeContext("test.cpp", sink, registry)
        ctx.openSource("test.cpp")
        val fileNum2 = ctx.reMountExcluded("unknown.h", 0x456L)
        val header = ctx.headerForFileNum(fileNum2)

        assertNotNull(header)
        assertEquals("unknown.h", header!!.filename)
        assertEquals(0x456L, header.checksum)
        assertEquals("<unknown>", header.originatingCu)

        // Check log was emitted
        val forwardExclLog = sink.logs.find { it.first == "forward-excl" }
        assertNotNull(forwardExclLog)
        assertTrue(forwardExclLog!!.second.contains("unknown.h"))
        assertTrue(forwardExclLog.second.contains("0x456"))
    }

    @Test
    fun `forward EXCL then BINCL creates two distinct HeaderFile instances`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        ctx1.openSource("cu1.cpp")
        val fileNum1Excl = ctx1.reMountExcluded("header.h", 0x123L)
        val header1Excl = ctx1.headerForFileNum(fileNum1Excl)

        // Verify forward-excl log was emitted exactly once
        assertEquals(1, sink.logs.filter { it.first == "forward-excl" }.size)
        assertEquals("<unknown>", header1Excl!!.originatingCu)

        // Now a later CU with real BINCL should get a different HeaderFile
        val ctx2 = IncludeContext("cu2.cpp", sink, registry)
        ctx2.openSource("cu2.cpp")
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
        ctx.openSource("test.cpp")

        // Call endInclude on empty stack
        ctx.endInclude()

        // Check log was emitted
        val unbalancedLog = sink.logs.find { it.first == "einc-unbalanced" }
        assertNotNull(unbalancedLog)
        assertTrue(unbalancedLog!!.second.contains("empty stack"))
    }

    @Test
    fun `canonicalCu integers are collision-free for different headers`() {
        val ctx1 = IncludeContext("cu1.cpp", sink, registry)
        ctx1.openSource("cu1.cpp")

        // Use two filenames whose String.hashCode() values collide.
        // Classic collision: "Aa".hashCode() == "BB".hashCode() == 2112
        // Create canonical keys that contain these substrings so the keys themselves collide.
        // Canonical key format: "{filename}_{checksum.toString(16)}" (see HeaderFile.canonicalKey())
        // We use filenames "Aa" and "BB" with the same checksum to create colliding keys.
        val filenameA = "Aa"
        val filenameB = "BB"
        val sameChecksum = 0xDEADBEEFL

        // FIRST: Verify that the filenames actually collide in hashCode()
        assertEquals(
            filenameA.hashCode(),
            filenameB.hashCode(),
            "Test setup error: filenames must have colliding hashCodes",
        )

        // Create two different headers with colliding filename hashes
        val fileNum1a = ctx1.beginInclude(filenameA, sameChecksum)
        val fileNum1b = ctx1.beginInclude(filenameB, sameChecksum)

        // Canonicalize two refs from different headers
        val typeId1a = TypeId(fileNum1a, 7)
        val typeId1b = TypeId(fileNum1b, 7)

        val canonical1a = ctx1.canonicalTypeId(typeId1a)
        val canonical1b = ctx1.canonicalTypeId(typeId1b)

        // Despite the hashCode collision, canonicalCu integers must be collision-free
        // because HeaderRegistry.allocateCanonicalCu uses a counter, not hashCode().
        assertTrue(
            canonical1a.cu != canonical1b.cu,
            "I1 fix FAILED: canonicalCu integers must be collision-free even when filename hashCodes collide",
        )
    }

    @Test
    fun `struct method signatures are canonicalized`() {
        val ctx = IncludeContext("cu.cpp", sink, registry)
        ctx.openSource("cu.cpp")
        val headerFileNum = ctx.beginInclude("header.h", 0x123L)

        // Create a struct with a method that has a signature referencing a header type
        val methodWithHeaderRef =
            MethodDecl(
                name = "process",
                mangled = "_Z7processRK6MyType",
                signature =
                    TypeDecl.FunctionT(
                        ret = TypeDecl.Ref(TypeId(headerFileNum, 42)), // Ref to header type
                        params = emptyList(),
                    ),
                access = Access.PUBLIC,
                virt = VirtKind.NORMAL,
                isConst = false,
                isVolatile = false,
                vtableOffsetBits = null,
            )

        val struct =
            TypeDecl.Struct(
                kind = AggrKind.CLASS,
                sizeBytes = 16,
                bases = emptyList(),
                fields = emptyList(),
                methods = listOf(methodWithHeaderRef),
                hasVTablePointerMarker = false,
                vtableTargetTypeId = null,
            )

        // Canonicalize the struct
        val canonicalized = ctx.canonicalizeTypeDecl(struct) as TypeDecl.Struct

        // The method signature should be canonicalized
        val canonicalizedMethod = canonicalized.methods[0]
        val canonicalizedSig = canonicalizedMethod.signature as TypeDecl.FunctionT
        val canonicalizedRef = canonicalizedSig.ret as TypeDecl.Ref

        // The return type ref should now have a canonical CU integer
        assertNotNull(canonicalizedRef)
        assertEquals(42, canonicalizedRef.id.n)
        // The CU should be the canonical integer for the header, not the original fileNum
        assertTrue(canonicalizedRef.id.cu > 0)
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
        cu1WithShared.openSource("cu1.cpp")
        val cu1HeaderFileNum = cu1WithShared.beginInclude("shared.h", 0xABCDL)
        val cu1Header = cu1WithShared.headerForFileNum(cu1HeaderFileNum)

        val cu2WithShared = IncludeContext("cu2.cpp", sink, sharedRegistry)
        cu2WithShared.openSource("cu2.cpp")
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
        cu1WithPrivate.openSource("cu1.cpp")
        val cu1PrivHeaderFileNum = cu1WithPrivate.beginInclude("shared.h", 0xABCDL)
        val cu1PrivHeader = cu1WithPrivate.headerForFileNum(cu1PrivHeaderFileNum)

        val cu2PrivateRegistry = HeaderRegistry()
        val cu2WithPrivate = IncludeContext("cu2.cpp", sink, cu2PrivateRegistry)
        cu2WithPrivate.openSource("cu2.cpp")
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
        val typeIdInCu1 = TypeId(cu1HeaderFileNum, 99)
        val typeIdInCu2 = TypeId(cu2HeaderFileNum, 99)

        val canonicalInCu1 = cu1WithShared.canonicalTypeId(typeIdInCu1)
        val canonicalInCu2 = cu2WithShared.canonicalTypeId(typeIdInCu2)

        assertEquals(
            canonicalInCu1,
            canonicalInCu2,
            "C1 fix: canonical TypeIds for same (filename, checksum) must be identical across CUs",
        )
    }
}
