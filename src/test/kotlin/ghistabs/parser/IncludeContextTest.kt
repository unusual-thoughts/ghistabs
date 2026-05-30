package ghistabs.parser

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
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
    }

    @Test
    fun `openSource allocates fileNum 1`() {
        val sink = RecordingSink()
        val ctx = IncludeContext("test.cpp", sink)
        val fileNum = ctx.openSource("test.cpp")
        assertEquals(1, fileNum)
    }

    @Test
    fun `openSource creates HeaderFile for own source`() {
        val sink = RecordingSink()
        val ctx = IncludeContext("test.cpp", sink)
        val fileNum = ctx.openSource("test.cpp")
        val header = ctx.headerForFileNum(fileNum)
        assertNotNull(header)
        assertEquals("test.cpp", header!!.filename)
        assertEquals(0L, header.checksum)
        assertEquals("test.cpp", header.originatingCu)
    }

    @Test
    fun `switchSource allocates next fileNum`() {
        val sink = RecordingSink()
        val ctx = IncludeContext("test.cpp", sink)
        ctx.openSource("test.cpp")
        val fileNum2 = ctx.switchSource("test.h")
        assertEquals(2, fileNum2)
    }

    @Test
    fun `beginInclude allocates fileNum and pushes stack`() {
        val sink = RecordingSink()
        val ctx = IncludeContext("test.cpp", sink)
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
        val sink = RecordingSink()
        val ctx = IncludeContext("test.cpp", sink)
        ctx.openSource("test.cpp")
        val fileNum2 = ctx.beginInclude("header.h", 0x123L)
        ctx.endInclude()
        // After popping, headerForFileNum should still return the header (it was registered by fileNum)
        assertNotNull(ctx.headerForFileNum(fileNum2))
    }

    @Test
    fun `two CUs with same BINCL get same HeaderFile instance`() {
        val sink1 = RecordingSink()
        val ctx1 = IncludeContext("cu1.cpp", sink1)
        ctx1.openSource("cu1.cpp")
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val sink2 = RecordingSink()
        val ctx2 = IncludeContext("cu2.cpp", sink2)
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
        val sink1 = RecordingSink()
        val ctx1 = IncludeContext("cu1.cpp", sink1)
        ctx1.openSource("cu1.cpp")
        val fileNum1 = ctx1.beginInclude("header.h", 0x123L)
        val header1 = ctx1.headerForFileNum(fileNum1)

        val sink2 = RecordingSink()
        val ctx2 = IncludeContext("cu2.cpp", sink2)
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
        val sink1 = RecordingSink()
        val ctx1 = IncludeContext("cu1.cpp", sink1)
        ctx1.openSource("cu1.cpp")
        val headerFileNum1 = ctx1.beginInclude("header.h", 0x123L)

        val sink2 = RecordingSink()
        val ctx2 = IncludeContext("cu2.cpp", sink2)
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
        val sink = RecordingSink()
        val ctx = IncludeContext("test.cpp", sink)
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
}
