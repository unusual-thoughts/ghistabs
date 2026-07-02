package ghistabs.diagnose

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class StabsDiagnosticsTest {
    @Test
    fun testDiagnosticsSummaryEmission() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.log("unresolved-ref", "ref=null in myFunction")
        diag.log("placeholder-created", "name=MyClass category=MyCategory reason=fwd-decl")
        diag.log("dedup-rename", "name=SomeType detail=renamed-to-SomeType_1")
        diag.log("vtable-applied", "class=VirtualBase")

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

        diag.log("unresolved-ref", "ref=null in fn")

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

        diag.log("unresolved-ref", "ref=cu1/1 in f1")
        diag.log("unresolved-ref", "ref=cu2/2 in f2")
        diag.log("placeholder-created", "name=T1 category=cat reason=reason1")
        diag.log("placeholder-created", "name=T2 category=cat reason=reason2")
        diag.log("placeholder-created", "name=T3 category=cat reason=reason3")

        assertEquals(2, diag["unresolved-ref"])
        assertEquals(3, diag["placeholder-created"])

        val snapshot = diag.snapshotCounters()
        assertTrue(snapshot.containsKey("unresolved-ref"))
        assertTrue(snapshot.containsKey("placeholder-created"))
    }

    @Test
    fun testCounterInsertionOrder() {
        val diag = StabsDiagnostics()

        diag.log("vtable-applied", "class=C1")
        diag.log("unresolved-ref", "ref=null in f")
        diag.log("placeholder-created", "name=T1 category=cat reason=reason")
        diag.log("dedup-rename")
        diag.log("global-applied", "addr=0x1000 dtKind=int")

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

        repeat(15) { i -> diag.log("unresolved-ref", "ref=null in fn$i") }

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        val exampleLines = output.split("\n").filter { it.contains("  - ref=") }
        assertEquals(10, exampleLines.size)
    }

    @Test
    fun testCountersReadableAfterSealing() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.log("unresolved-ref", "ref=null in f")
        diag.log("placeholder-created", "name=T category=cat reason=reason")

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
    fun testCapturingSinkRecordsEveryTag() {
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
