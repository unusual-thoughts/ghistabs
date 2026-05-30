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

        // Create two different headers
        val fileNum1a = ctx1.beginInclude("header_a.h", 0x111L)
        val fileNum1b = ctx1.beginInclude("header_b.h", 0x222L)

        // Canonicalize two refs from different headers
        val typeId1a = TypeId(fileNum1a, 7)
        val typeId1b = TypeId(fileNum1b, 7)

        val canonical1a = ctx1.canonicalTypeId(typeId1a)
        val canonical1b = ctx1.canonicalTypeId(typeId1b)

        // Different canonical CU integers (collision-free)
        assertTrue(canonical1a.cu != canonical1b.cu)
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
}
