package ghistabs

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

/**
 * `a..<b` is the only operator here that can be handed a degenerate pair, and Ghidra will not report
 * one: [ghidra.program.model.address.AddressRangeImpl]'s two-address constructor silently swaps
 * bounds that arrive out of order, so `a..<a` would come back as `[a-1, a]` — a range starting below
 * where the caller said. Built by length instead, the degenerate cases are empty and contain nothing.
 */
class AddressOperatorTest {
    private fun addr(offset: Long) = GenericAddressResolver.buildAddress(offset)

    @Test
    fun `exclusive end stops one short`() {
        val range = addr(0x100)..<addr(0x110)
        assertEquals(addr(0x100), range.minAddress)
        assertEquals(addr(0x10f), range.maxAddress)
        assertEquals(0x10L, range.length)
    }

    @Test
    fun `one-byte range is the shortest expressible`() {
        val range = addr(0x100)..<addr(0x101)
        assertEquals(addr(0x100), range.minAddress)
        assertEquals(addr(0x100), range.maxAddress)
        assertEquals(1L, range.length)
    }

    @Test
    fun `an end at the start is empty, not widened downwards`() {
        val range = addr(0x100)..<addr(0x100)
        assertEquals(0L, range.length)
        assertFalse(range.contains(addr(0x100)))
        assertFalse(range.contains(addr(0xff)))
    }

    @Test
    fun `an end below the start is empty, not swapped`() {
        val range = addr(0x110)..<addr(0x100)
        assertEquals(0L, range.length)
        assertFalse(range.contains(addr(0x108)))
    }
}
