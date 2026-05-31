package ghistabs.diag

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for gap computation algorithm.
 * Tests the computeGaps function which identifies holes in struct field layouts.
 */
class GapComputationTest {
    data class ComponentRecord(
        val fieldName: String,
        val offsetBytes: Int,
        val lengthBytes: Int,
    )

    /**
     * Compute gaps in a struct's field layout.
     * Returns a list of gaps between consecutive fields.
     * Gaps at the start (before first field) are not reported.
     * Trailing gaps (after last field) are reported.
     */
    fun computeGaps(componentRecords: List<ComponentRecord>, totalLengthBytes: Int): List<GapRecord> {
        if (componentRecords.isEmpty()) return emptyList()

        val gaps = mutableListOf<GapRecord>()
        val sorted = componentRecords.sortedBy { it.offsetBytes }

        // Check for gaps between consecutive fields
        for (i in 0 until sorted.size - 1) {
            val current = sorted[i]
            val next = sorted[i + 1]
            val currentEnd = current.offsetBytes + current.lengthBytes
            if (currentEnd < next.offsetBytes) {
                val gapLength = next.offsetBytes - currentEnd
                gaps.add(
                    GapRecord(
                        offsetBits = (currentEnd * 8).toLong(),
                        lengthBits = (gapLength * 8).toLong(),
                        prevField = current.fieldName,
                        nextField = next.fieldName,
                    ),
                )
            }
        }

        // Check for trailing gap
        val lastComponent = sorted.last()
        val lastEnd = lastComponent.offsetBytes + lastComponent.lengthBytes
        if (lastEnd < totalLengthBytes) {
            val trailingGapLength = totalLengthBytes - lastEnd
            gaps.add(
                GapRecord(
                    offsetBits = (lastEnd * 8).toLong(),
                    lengthBits = (trailingGapLength * 8).toLong(),
                    prevField = lastComponent.fieldName,
                    nextField = null,
                ),
            )
        }

        return gaps
    }

    @Test
    fun `empty components returns no gaps`() {
        val gaps = computeGaps(emptyList(), 16)
        assertTrue(gaps.isEmpty())
    }

    @Test
    fun `single component with no trailing gap returns no gaps`() {
        val components = listOf(
            ComponentRecord("field0", 0, 4),
        )
        val gaps = computeGaps(components, 4)
        assertTrue(gaps.isEmpty())
    }

    @Test
    fun `single component with trailing gap reports gap`() {
        val components = listOf(
            ComponentRecord("field0", 0, 4),
        )
        val gaps = computeGaps(components, 8)
        assertEquals(1, gaps.size)
        assertEquals(4 * 8, gaps[0].offsetBits)
        assertEquals(4 * 8, gaps[0].lengthBits)
        assertEquals("field0", gaps[0].prevField)
        assertEquals(null, gaps[0].nextField)
    }

    @Test
    fun `gap between two consecutive fields`() {
        val components = listOf(
            ComponentRecord("field0", 0, 4),
            ComponentRecord("field1", 8, 4),
        )
        val gaps = computeGaps(components, 12)
        assertEquals(1, gaps.size)
        assertEquals(4 * 8, gaps[0].offsetBits)
        assertEquals(4 * 8, gaps[0].lengthBits)
        assertEquals("field0", gaps[0].prevField)
        assertEquals("field1", gaps[0].nextField)
    }

    @Test
    fun `multiple gaps and trailing gap`() {
        val components = listOf(
            ComponentRecord("field0", 0, 4),
            ComponentRecord("field1", 8, 4),
        )
        val gaps = computeGaps(components, 16)
        assertEquals(2, gaps.size)
        // Gap between fields
        assertEquals(4 * 8, gaps[0].offsetBits)
        assertEquals(4 * 8, gaps[0].lengthBits)
        assertEquals("field0", gaps[0].prevField)
        assertEquals("field1", gaps[0].nextField)
        // Trailing gap
        assertEquals(12 * 8, gaps[1].offsetBits)
        assertEquals(4 * 8, gaps[1].lengthBits)
        assertEquals("field1", gaps[1].prevField)
        assertEquals(null, gaps[1].nextField)
    }

    @Test
    fun `fully packed struct returns no gaps`() {
        val components = listOf(
            ComponentRecord("field0", 0, 4),
            ComponentRecord("field1", 4, 4),
            ComponentRecord("field2", 8, 4),
        )
        val gaps = computeGaps(components, 12)
        assertTrue(gaps.isEmpty())
    }

    @Test
    fun `unsorted components are sorted before gap computation`() {
        val components = listOf(
            ComponentRecord("field2", 8, 2),
            ComponentRecord("field0", 0, 4),
            ComponentRecord("field1", 6, 2),
        )
        val gaps = computeGaps(components, 10)
        assertEquals(1, gaps.size)
        // Gap between field0 (ends at 4) and field1 (starts at 6)
        assertEquals(4 * 8, gaps[0].offsetBits)
        assertEquals(2 * 8, gaps[0].lengthBits)
    }
}
