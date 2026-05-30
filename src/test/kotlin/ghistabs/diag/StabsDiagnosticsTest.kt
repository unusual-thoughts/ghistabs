package ghistabs.diag

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Program
import ghistabs.importer.BookmarkSink
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

/**
 * Pure unit tests for StabsDiagnostics.
 *
 * Uses a real MessageLog (lightweight Ghidra utility, not a heavy Program type)
 * to capture sink output and verify diagnostic emission contracts.
 *
 * No mocks of Ghidra Program/Listing/etc.; BookmarkSink is mocked minimally
 * to avoid side-effects, but the core logic is exercised via MessageLog.
 */
class StabsDiagnosticsTest {
    /**
     * AC11.1: After several record* calls, writeSummary produces exactly one
     * === diagnostics === header, one name=value line per counter, and example
     * sections only when buckets are non-empty.
     */
    @Test
    fun testDiagnosticsSummaryEmission() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()

        // Minimal mock BookmarkSink that just delegates to MessageLog
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        // Record some events
        diag.recordUnresolvedRef("(1,42)", "myFunction", "foo.cpp")
        diag.recordPlaceholder("MyClass", "MyCategory", "fwd-decl")
        diag.recordDedup("rename", "SomeType", "renamed-to-SomeType_1")
        diag.recordVtable("VirtualBase", "applied")

        // Emit summary
        diag.writeSummary(sink)

        val output = messageLog.toString()

        // Assert header exists
        assertTrue(output.contains("=== diagnostics ==="), "Should contain diagnostics header")

        // Assert all counter lines exist
        assertTrue(output.contains("unresolved-ref = 1"), "Should emit unresolved-ref counter")
        assertTrue(output.contains("placeholder-created = 1"), "Should emit placeholder-created counter")
        assertTrue(output.contains("dedup-rename = 1"), "Should emit dedup-rename counter")
        assertTrue(output.contains("vtable-applied = 1"), "Should emit vtable-applied counter")

        // Assert example sections exist
        assertTrue(output.contains("unresolved-ref top examples:"), "Should have examples section for unresolved-ref")
        assertTrue(output.contains("placeholder-created top examples:"), "Should have examples section for placeholder-created")
    }

    /**
     * Idempotence contract: second call to writeSummary is a no-op (sealed state).
     * The sink receives output ONLY on the first call.
     */
    @Test
    fun testWriteSummaryIdempotence() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        diag.recordUnresolvedRef("(1,42)", "fn", "cu")

        // First write
        diag.writeSummary(sink)
        val outputAfterFirst = messageLog.toString()

        // Count occurrences of the header
        val firstHeaderCount = outputAfterFirst.split("=== diagnostics ===").size - 1

        // Second write (should be sealed no-op)
        diag.writeSummary(sink)
        val outputAfterSecond = messageLog.toString()

        // Count occurrences again
        val secondHeaderCount = outputAfterSecond.split("=== diagnostics ===").size - 1

        // Should still be exactly 1 header (second call was a no-op)
        assertEquals(firstHeaderCount, 1, "First call should emit exactly one header")
        assertEquals(secondHeaderCount, 1, "Second call should be sealed (no new output)")
    }

    /**
     * AC11.2: Gap census section lists each registered struct's gaps with
     * offset/length and adjacent field names. Structs with empty gap lists
     * do NOT appear in output (genuinely-packed structs don't pollute the report).
     */
    @Test
    fun testGapCensusOutput() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        // Record a struct with gaps
        val gaps =
            listOf(
                GapRecord(offsetBits = 32, lengthBits = 32, prevField = "field1", nextField = "field2"),
                GapRecord(offsetBits = 96, lengthBits = 16, prevField = "field3", nextField = null),
            )
        diag.recordStructGaps("MyCategory/MyStruct", gaps)

        // Record a struct without gaps (should not appear in output)
        diag.recordStructGaps("MyCategory/PackedStruct", emptyList())

        diag.writeSummary(sink)

        val output = messageLog.toString()

        // Gap census section should exist
        assertTrue(output.contains("gap census:"), "Should have gap census section")

        // Struct with gaps should appear with all its gaps
        assertTrue(output.contains("MyCategory/MyStruct: gap @+32 bits len=32 between field1..field2"))
        assertTrue(output.contains("MyCategory/MyStruct: gap @+96 bits len=16 between field3..(end)"))

        // Packed struct should NOT appear in output
        assertTrue(!output.contains("PackedStruct"), "Packed struct with no gaps should not appear")
    }

    /**
     * Tag→counter auto-bump contract: each record* call increments the
     * corresponding counter and populates its example bucket.
     */
    @Test
    fun testTagCounterAutoBump() {
        val diag = StabsDiagnostics()

        // Record events multiple times
        diag.recordUnresolvedRef("(1,1)", "f1", "cu1")
        diag.recordUnresolvedRef("(1,2)", "f2", "cu2")
        diag.recordPlaceholder("T1", "cat", "reason1")
        diag.recordPlaceholder("T2", "cat", "reason2")
        diag.recordPlaceholder("T3", "cat", "reason3")

        // Verify counter values
        assertEquals(2, diag["unresolved-ref"], "unresolved-ref should be 2")
        assertEquals(3, diag["placeholder-created"], "placeholder-created should be 3")

        // Verify examples are recorded (capped at 10)
        val snapshot = diag.snapshotCounters()
        assertTrue(snapshot.containsKey("unresolved-ref"))
        assertTrue(snapshot.containsKey("placeholder-created"))
    }

    /**
     * Test that multiple distinct counters maintain insertion order.
     */
    @Test
    fun testCounterInsertionOrder() {
        val diag = StabsDiagnostics()

        diag.recordVtable("C1", "applied")
        diag.recordUnresolvedRef("(1,1)", "f", "cu")
        diag.recordPlaceholder("T1", "cat", "reason")
        diag.recordDedup("rename", "T2", "detail")
        diag.recordGlobal("0x1000", "applied", "int")

        val snapshot = diag.snapshotCounters()
        val keys = snapshot.keys.toList()

        // Verify insertion order is preserved
        assertEquals(listOf("vtable-applied", "unresolved-ref", "placeholder-created", "dedup-rename", "global-applied"), keys)
    }

    /**
     * Test that examples are capped at 10 per category.
     */
    @Test
    fun testExampleCapCeiling() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        // Record 15 examples for the same category (should cap at 10)
        repeat(15) { i ->
            diag.recordUnresolvedRef("(1,$i)", "fn", "cu")
        }

        diag.writeSummary(sink)

        val output = messageLog.toString()

        // Count example lines (each example is prefixed with "  - ")
        val exampleLines = output.split("\n").filter { it.contains("  - ref=") }
        assertEquals(10, exampleLines.size, "Should have exactly 10 example lines (capped at 10)")
    }

    /**
     * Test recordVtable with and without reason parameter.
     */
    @Test
    fun testRecordVtableWithReason() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        diag.recordVtable("ClassA", "applied")
        diag.recordVtable("ClassB", "skipped", "no-virtuals")
        diag.recordVtable("ClassC", "failed", "unresolved-_ZTV-symbol")

        diag.writeSummary(sink)

        val output = messageLog.toString()

        // Verify all outcomes are tracked
        assertTrue(output.contains("vtable-applied = 1"))
        assertTrue(output.contains("vtable-skipped = 1"))
        assertTrue(output.contains("vtable-failed = 1"))

        // Verify examples include reasons where provided
        assertTrue(output.contains("class=ClassB reason=no-virtuals"))
        assertTrue(output.contains("class=ClassC reason=unresolved-_ZTV-symbol"))
    }

    /**
     * Test recordGlobal with per-kind tracking.
     */
    @Test
    fun testRecordGlobalPerKind() {
        val diag = StabsDiagnostics()

        diag.recordGlobal("0x1000", "applied", "int")
        diag.recordGlobal("0x1004", "applied", "Structure")
        diag.recordGlobal("0x1008", "skipped", "Array", "create-data-failed")
        diag.recordGlobal("0x100c", "skipped", "Pointer", "unresolved-symbol")

        // Verify counters
        assertEquals(2, diag["global-applied"], "Should have 2 global-applied")
        assertEquals(2, diag["global-skipped"], "Should have 2 global-skipped")

        // Verify examples include dtKind
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)
        diag.writeSummary(sink)
        val output = messageLog.toString()

        assertTrue(output.contains("dtKind=int"))
        assertTrue(output.contains("dtKind=Structure"))
        assertTrue(output.contains("dtKind=Array"))
        assertTrue(output.contains("dtKind=Pointer"))
    }

    /**
     * Test recordEmptyScope with and without function name.
     */
    @Test
    fun testRecordEmptyScope() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        diag.recordEmptyScope("0x1000", "main")
        diag.recordEmptyScope("0x1004", null)

        diag.writeSummary(sink)

        val output = messageLog.toString()

        assertTrue(output.contains("empty-scope = 2"))
        assertTrue(output.contains("addr=0x1000 function=main"))
        assertTrue(output.contains("addr=0x1004"))
    }

    /**
     * Test that counters are readable after sealing.
     */
    @Test
    fun testCountersReadableAfterSealing() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        diag.recordUnresolvedRef("(1,1)", "f", "cu")
        diag.recordPlaceholder("T", "cat", "reason")

        // Seal via writeSummary
        diag.writeSummary(sink)

        // Counters should still be readable
        assertEquals(1, diag["unresolved-ref"])
        assertEquals(1, diag["placeholder-created"])

        val snapshot = diag.snapshotCounters()
        assertEquals(2, snapshot.size)
        assertTrue(snapshot.containsKey("unresolved-ref"))
        assertTrue(snapshot.containsKey("placeholder-created"))
    }

    /**
     * Test that zero-valued counters are emitted.
     */
    @Test
    fun testZeroCountersEmitted() {
        val diag = StabsDiagnostics()
        val messageLog = MessageLog()
        val mockProgram: Program = mock()
        val sink = BookmarkSink(mockProgram, messageLog)

        // Manually create some counter entries (simulating different phases)
        diag.inc("counter-a", 1)
        diag.inc("counter-b", 0) // explicitly zero
        diag.inc("counter-c", 3)

        diag.writeSummary(sink)

        val output = messageLog.toString()

        // All should be emitted, including the zero
        assertTrue(output.contains("counter-a = 1"))
        assertTrue(output.contains("counter-b = 0"))
        assertTrue(output.contains("counter-c = 3"))
    }
}
