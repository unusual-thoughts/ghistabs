package ghistabs.render

import ghistabs.GenericAddressResolver
import ghistabs.harvest.Func
import ghistabs.harvest.LineEntry
import ghistabs.parse.FunctionScope
import ghistabs.parse.SourceFile
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of [FunctionSpans.of]: the close-line choice (endLine+1, or
 * endLine when that collides with the next opener), the neighbor-clamp that rejects
 * a cross-attributed min-line, and the strict-containment drop. Fixtures are synthetic
 * [Func]s — no Ghidra program, no mocks.
 */
class FunctionSpansTest {
    // Line entries are addressed at `base + <position>` so the first-listed line is the
    // lowest-address entry, i.e. the prologue; `lines` order therefore sets the prologue.
    private fun fn(name: String, base: Long, source: String, lines: List<Int>) = Func(
        name = name,
        addr = GenericAddressResolver.buildAddress(base),
        decl = SymbolDecl.Function(name, FunctionScope.GLOBAL, TypeDecl.Builtin(-1)),
        cu = SourceFile.CUSource(source),
        lineEntries = lines.mapIndexed { i, l -> LineEntry(l, GenericAddressResolver.buildAddress(base + i), source) }
            .toMutableList(),
    )

    private fun FunctionSpans.closeOf(func: Func) = with(this) { ranges.single { it.func === func }.closeLine }
    private fun FunctionSpans.interiorOf(func: Func) = with(this) { ranges.single { it.func === func }.interior }

    @Test
    fun `non-adjacent functions close on endLine+1`() {
        val a = fn("a", 0x1000, "s.cpp", listOf(10, 11, 12))
        val b = fn("b", 0x2000, "s.cpp", listOf(20, 21, 22))
        val spans = FunctionSpans.of(listOf(a, b), "s.cpp")

        assertEquals(listOf(10..12, 20..22), spans.ranges.map { it.lines })
        assertEquals(13, spans.closeOf(a))
        assertEquals(23, spans.closeOf(b))
    }

    @Test
    fun `an opener on endLine+1 pulls the previous close up to endLine`() {
        val a = fn("a", 0x1000, "s.cpp", listOf(10, 11, 12))
        val b = fn("b", 0x2000, "s.cpp", listOf(13, 14)) // opens exactly where a would close
        val spans = FunctionSpans.of(listOf(a, b), "s.cpp")

        assertEquals(12, spans.closeOf(a)) // not 13 — would collide with b's opener
        assertEquals(15, spans.closeOf(b))
    }

    @Test
    fun `a cross-attributed min-line below the previous function falls back to the prologue`() {
        val a = fn("a", 0x1000, "s.cpp", listOf(10, 30)) // occupies L10..L30
        // b's lowest-address entry is L40 (the real prologue) but it also carries a stray
        // L5 — below a's end. Trusting the min would drag b's opener up into a's body.
        val b = fn("b", 0x2000, "s.cpp", listOf(40, 5, 41))
        val spans = FunctionSpans.of(listOf(a, b), "s.cpp")

        val bRange = spans.ranges.single { it.func === b }
        assertEquals(40, bRange.start) // clamped to prologue, not 5
    }

    @Test
    fun `a range strictly contained in another is dropped`() {
        val outer = fn("outer", 0x1000, "s.cpp", listOf(10, 50))
        val inner = fn("inner", 0x2000, "s.cpp", listOf(20, 30)) // 20..30 ⊂ 10..50
        val spans = FunctionSpans.of(listOf(outer, inner), "s.cpp")

        assertEquals(listOf(outer), spans.ranges.map { it.func })
    }

    @Test
    fun `a single-line range has no close line but still occupies its line`() {
        val f = fn("f", 0x1000, "s.cpp", listOf(10))
        val spans = FunctionSpans.of(listOf(f), "s.cpp")

        assertEquals(1, spans.ranges.size)
        assertNull(spans.closeOf(f))
        assertEquals(true, spans.inFunction(10))
    }

    // The interior is what `reportAnomalies` scans for a function/type/global filed inside
    // another function's brackets; an empty one silences the whole diagnostic.
    @Test
    fun `interior is the lines strictly between the brackets, in both close-line cases`() {
        val a = fn("a", 0x1000, "s.cpp", listOf(10, 11, 12)) // closes on 13
        val b = fn("b", 0x2000, "s.cpp", listOf(20, 21, 22))
        assertEquals(11..12, FunctionSpans.of(listOf(a, b), "s.cpp").interiorOf(a))

        val c = fn("c", 0x2000, "s.cpp", listOf(13, 14)) // opens where a would close, pulling it to 12
        assertEquals(11..11, FunctionSpans.of(listOf(a, c), "s.cpp").interiorOf(a))
    }

    @Test
    fun `a prologue line above the last-address line is normalised, not left inverted`() {
        // Nothing names s.cpp, so rawSpan falls back to every entry in *address* order — and gcc
        // emits N_SLINEs out of it, so the prologue (L50) can outrank the last entry (L10).
        val f = fn("f", 0x1000, "hdr.h", listOf(50, 10))
        val spans = FunctionSpans.of(listOf(f), "s.cpp")

        assertEquals(10..50, spans.ranges.single().lines)
        assertEquals(51, spans.closeOf(f))
    }
}
