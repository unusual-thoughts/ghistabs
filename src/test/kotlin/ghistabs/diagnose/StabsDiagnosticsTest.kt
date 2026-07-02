package ghistabs.diagnose

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StabsDiagnosticsTest {
    private fun gid(cu: String, n: Int) = GlobalTypeId(SourceFile.CUSource(cu), n)

    @Test
    fun testDiagnosticsSummaryEmission() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.recordUnresolvedRef(null, "myFunction")
        diag.recordPlaceholder("MyClass", "MyCategory", "fwd-decl")
        diag.recordExample("dedup-rename", "name=SomeType detail=renamed-to-SomeType_1")
        diag.log("dedup-rename")
        diag.recordVtable("VirtualBase", "applied")

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("=== diagnostics ==="))
        assertTrue(output.contains("unresolved-ref = 1"))
        assertTrue(output.contains("placeholder-created = 1"))
        assertTrue(output.contains("dedup-rename = 1"))
        assertTrue(output.contains("vtable-applied = 1"))
        assertTrue(output.contains("unresolved-ref top examples:"))
        assertTrue(output.contains("placeholder-created top examples:"))
    }

    @Test
    fun testWriteSummaryIdempotence() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.recordUnresolvedRef(null, "fn")

        diag.writeSummary(sink)
        val firstHeaderCount = sink.capturedOutput().split("=== diagnostics ===").size - 1

        diag.writeSummary(sink)
        val secondHeaderCount = sink.capturedOutput().split("=== diagnostics ===").size - 1

        assertEquals(1, firstHeaderCount)
        assertEquals(1, secondHeaderCount)
    }

    @Test
    fun testGapCensusOutput() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        val gaps = listOf(
            GapRecord(offsetBits = 32, lengthBits = 32, prevField = "field1", nextField = "field2"),
            GapRecord(offsetBits = 96, lengthBits = 16, prevField = "field3", nextField = null),
        )
        diag.recordStructGaps("MyCategory/MyStruct", gaps)
        diag.recordStructGaps("MyCategory/PackedStruct", emptyList())

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("gap census:"))
        assertTrue(output.contains("MyCategory/MyStruct: gap @+32 bits len=32 between field1..field2"))
        assertTrue(output.contains("MyCategory/MyStruct: gap @+96 bits len=16 between field3..(end)"))
        assertTrue(!output.contains("PackedStruct"))
    }

    @Test
    fun testTagCounterAutoBump() {
        val diag = StabsDiagnostics()

        diag.recordUnresolvedRef(gid("cu1", 1), "f1")
        diag.recordUnresolvedRef(gid("cu2", 2), "f2")
        diag.recordPlaceholder("T1", "cat", "reason1")
        diag.recordPlaceholder("T2", "cat", "reason2")
        diag.recordPlaceholder("T3", "cat", "reason3")

        assertEquals(2, diag["unresolved-ref"])
        assertEquals(3, diag["placeholder-created"])

        val snapshot = diag.snapshotCounters()
        assertTrue(snapshot.containsKey("unresolved-ref"))
        assertTrue(snapshot.containsKey("placeholder-created"))
    }

    @Test
    fun testCounterInsertionOrder() {
        val diag = StabsDiagnostics()

        diag.recordVtable("C1", "applied")
        diag.recordUnresolvedRef(null, "f")
        diag.recordPlaceholder("T1", "cat", "reason")
        diag.log("dedup-rename")
        diag.recordGlobal("0x1000", "applied", "int")

        val keys = diag.snapshotCounters().keys.toList()
        assertEquals(
            listOf("vtable-applied", "unresolved-ref", "placeholder-created", "dedup-rename", "global-applied"),
            keys,
        )
    }

    @Test
    fun testExampleCapCeiling() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        repeat(15) { i ->
            diag.recordUnresolvedRef(null, "fn$i")
        }

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        val exampleLines = output.split("\n").filter { it.contains("  - ref=") }
        assertEquals(10, exampleLines.size)
    }

    @Test
    fun testRecordVtableWithReason() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.recordVtable("ClassA", "applied")
        diag.recordVtable("ClassB", "skipped", "no-virtuals")
        diag.recordVtable("ClassC", "failed", "unresolved-_ZTV-symbol")

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("vtable-applied = 1"))
        assertTrue(output.contains("vtable-skipped = 1"))
        assertTrue(output.contains("vtable-failed = 1"))
        assertTrue(output.contains("class=ClassB reason=no-virtuals"))
        assertTrue(output.contains("class=ClassC reason=unresolved-_ZTV-symbol"))
    }

    @Test
    fun testRecordGlobalPerKind() {
        val diag = StabsDiagnostics()

        diag.recordGlobal("0x1000", "applied", "int")
        diag.recordGlobal("0x1004", "applied", "Structure")
        diag.recordGlobal("0x1008", "skipped", "Array", "create-data-failed")
        diag.recordGlobal("0x100c", "skipped", "Pointer", "unresolved-symbol")

        assertEquals(2, diag["global-applied"])
        assertEquals(2, diag["global-skipped"])

        val sink = CapturingSink()
        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("dtKind=int"))
        assertTrue(output.contains("dtKind=Structure"))
        assertTrue(output.contains("dtKind=Array"))
        assertTrue(output.contains("dtKind=Pointer"))
    }

    @Test
    fun testRecordEmptyScope() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.recordEmptyScope("0x1000", "main")
        diag.recordEmptyScope("0x1004", null)

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("empty-scope = 2"))
        assertTrue(output.contains("addr=0x1000 function=main"))
        assertTrue(output.contains("addr=0x1004"))
    }

    @Test
    fun testCountersReadableAfterSealing() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.recordUnresolvedRef(null, "f")
        diag.recordPlaceholder("T", "cat", "reason")

        diag.writeSummary(sink)

        assertEquals(1, diag["unresolved-ref"])
        assertEquals(1, diag["placeholder-created"])

        val snapshot = diag.snapshotCounters()
        assertEquals(2, snapshot.size)
        assertTrue(snapshot.containsKey("unresolved-ref"))
        assertTrue(snapshot.containsKey("placeholder-created"))
    }

    @Test
    fun testZeroCountersEmitted() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.log("counter-a", count = 1)
        diag.log("counter-b", count = 0)
        diag.log("counter-c", count = 3)

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("counter-a = 1"))
        assertTrue(output.contains("counter-b = 0"))
        assertTrue(output.contains("counter-c = 3"))
    }

    @Test
    fun testDiagnosticSinkAutoIncCounters() {
        val sink = CapturingSink()

        sink.log("foo-tag", "first message")
        sink.log("foo-tag", "second message")
        sink.log("bar-tag", "a message")
        sink.log("foo-tag", "third message")

        val output = sink.capturedOutput()
        assertTrue(output.contains("foo-tag"))
        assertTrue(output.contains("bar-tag"))
    }

    @Test
    fun testRecordStructGapsLastDefinitionWins() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        val gapsA = listOf(GapRecord(offsetBits = 32, lengthBits = 32, prevField = "a", nextField = "b"))
        val gapsB = listOf(GapRecord(offsetBits = 64, lengthBits = 16, prevField = "x", nextField = "y"))

        diag.recordStructGaps("test/MyStruct", gapsA)
        diag.recordStructGaps("test/MyStruct", gapsB)

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        assertTrue(output.contains("test/MyStruct: gap @+64 bits len=16 between x..y"))
        assertTrue(!output.contains("test/MyStruct: gap @+32 bits len=32"))
    }
}
