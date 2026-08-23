package ghistabs.diagnose

import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustBeIn
import ghistabs.test.mustNotBeIn
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

        "=== diagnostics ===" mustBeIn output
        "unresolved-ref = 1" mustBeIn output
        "placeholder-created = 1" mustBeIn output
        "dedup-rename = 1" mustBeIn output
        "vtable-applied = 1" mustBeIn output
        "unresolved-ref top examples:" mustBeIn output
        "placeholder-created top examples:" mustBeIn output
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

        firstHeaderCount mustBe 1
        secondHeaderCount mustBe 1
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

        "gap census:" mustBeIn output
        "MyCategory/MyStruct: gap @+32 bits len=32 between field1..field2" mustBeIn output
        "MyCategory/MyStruct: gap @+96 bits len=16 between field3..(end)" mustBeIn output
        "PackedStruct" mustNotBeIn output
    }

    @Test
    fun testTagCounterAutoBump() {
        val diag = StabsDiagnostics()

        diag.log("unresolved-ref", "ref=cu1/1 in f1")
        diag.log("unresolved-ref", "ref=cu2/2 in f2")
        diag.log("placeholder-created", "name=T1 category=cat reason=reason1")
        diag.log("placeholder-created", "name=T2 category=cat reason=reason2")
        diag.log("placeholder-created", "name=T3 category=cat reason=reason3")

        diag["unresolved-ref"] mustBe 2
        diag["placeholder-created"] mustBe 3

        val snapshot = diag.snapshotCounters()
        snapshot.must { containsKey("unresolved-ref") }
        snapshot.must { containsKey("placeholder-created") }
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
        keys mustBe listOf("vtable-applied", "unresolved-ref", "placeholder-created", "dedup-rename", "global-applied")
    }

    @Test
    fun testExampleCapCeiling() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        repeat(15) { i -> diag.log("unresolved-ref", "ref=null in fn$i") }

        diag.writeSummary(sink)
        val output = sink.capturedOutput()

        val exampleLines = output.split("\n").filter { it.contains("  - ref=") }
        exampleLines.size mustBe 10
    }

    @Test
    fun testCountersReadableAfterSealing() {
        val diag = StabsDiagnostics()
        val sink = CapturingSink()

        diag.log("unresolved-ref", "ref=null in f")
        diag.log("placeholder-created", "name=T category=cat reason=reason")

        diag.writeSummary(sink)

        diag["unresolved-ref"] mustBe 1
        diag["placeholder-created"] mustBe 1

        val snapshot = diag.snapshotCounters()
        snapshot.size mustBe 2
        snapshot.must { containsKey("unresolved-ref") }
        snapshot.must { containsKey("placeholder-created") }
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

        "counter-a = 1" mustBeIn output
        "counter-b = 0" mustBeIn output
        "counter-c = 3" mustBeIn output
    }

    @Test
    fun testCapturingSinkRecordsEveryTag() {
        val sink = CapturingSink()

        sink.log("foo-tag", "first message")
        sink.log("foo-tag", "second message")
        sink.log("bar-tag", "a message")
        sink.log("foo-tag", "third message")

        val output = sink.capturedOutput()
        "foo-tag" mustBeIn output
        "bar-tag" mustBeIn output
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

        "test/MyStruct: gap @+64 bits len=16 between x..y" mustBeIn output
        "test/MyStruct: gap @+32 bits len=32" mustNotBeIn output
    }
}
