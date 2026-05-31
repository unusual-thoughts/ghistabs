package ghistabs.diag

import ghistabs.diag.BaselineCompare.parseDanglingRefBaseline
import ghistabs.diag.BaselineCompare.parseSuffixCountBaseline
import ghistabs.diag.BaselineCompare.passesReduction
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Kind 1 pure unit tests for BaselineCompare.
 * No Ghidra imports, no mocks.
 */
class BaselineCompareTest {
    @Test
    fun `parse valid baseline JSON with dangling-ref key`() {
        val tempFile = createTempFileWithContent("""{"dangling-ref": 12345}""")
        val result = parseDanglingRefBaseline(tempFile)
        assertEquals(12345L, result)
    }

    @Test
    fun `parse baseline with whitespace padding`() {
        val tempFile = createTempFileWithContent(
            """
                {
                  "dangling-ref"  :  98765
                }
            """.trimIndent(),
        )
        val result = parseDanglingRefBaseline(tempFile)
        assertEquals(98765L, result)
    }

    @Test
    fun `parse fails with missing dangling-ref key`() {
        val tempFile = createTempFileWithContent("""{"other-key": 123}""")
        assertThrows(IllegalArgumentException::class.java) {
            parseDanglingRefBaseline(tempFile)
        }
    }

    @Test
    fun `passesReduction boundary case - exactly ceil(baseline*ratio)`() {
        val baseline = 100L
        val ratio = 0.10
        // ceil(100 * 0.10) = ceil(10.0) = 10
        val threshold = 10L

        assertTrue(passesReduction(threshold, baseline, ratio))
        // Just over threshold
        assertFalse(passesReduction(threshold + 1, baseline, ratio))
    }

    @Test
    fun `passesReduction with baseline 0 returns true`() {
        assertTrue(passesReduction(0L, 0L, 0.10))
        assertTrue(passesReduction(100L, 0L, 0.10)) // No regression possible
    }

    @Test
    fun `passesReduction with fractional ratio`() {
        val baseline = 1000L
        val ratio = 0.05
        // ceil(1000 * 0.05) = ceil(50.0) = 50
        assertTrue(passesReduction(50L, baseline, ratio))
        assertFalse(passesReduction(51L, baseline, ratio))
    }

    @Test
    fun `passesReduction with small baseline and ratio`() {
        val baseline = 5L
        val ratio = 0.10
        // ceil(5 * 0.10) = ceil(0.5) = 1
        assertTrue(passesReduction(1L, baseline, ratio))
        assertFalse(passesReduction(2L, baseline, ratio))
    }

    @Test
    fun `passesReduction actual equals baseline`() {
        // Even if actual == baseline, threshold is typically much smaller,
        // so this should fail for default ratio
        assertFalse(passesReduction(100L, 100L, 0.10))
    }

    @Test
    fun `parse valid suffix count baseline JSON`() {
        val tempFile = createTempFileWithContent("""{"_N-suffix-count": 54321}""")
        val result = parseSuffixCountBaseline(tempFile)
        assertEquals(54321L, result)
    }

    @Test
    fun `parse suffix count baseline with whitespace`() {
        val tempFile = createTempFileWithContent(
            """
                {
                  "_N-suffix-count"  :  11111
                }
            """.trimIndent(),
        )
        val result = parseSuffixCountBaseline(tempFile)
        assertEquals(11111L, result)
    }

    @Test
    fun `parse suffix count fails with missing key`() {
        val tempFile = createTempFileWithContent("""{"other-key": 123}""")
        assertThrows(IllegalArgumentException::class.java) {
            parseSuffixCountBaseline(tempFile)
        }
    }

    @Test
    fun `parse suffix count with zero value`() {
        val tempFile = createTempFileWithContent("""{"_N-suffix-count": 0}""")
        val result = parseSuffixCountBaseline(tempFile)
        assertEquals(0L, result)
    }

    private fun createTempFileWithContent(content: String): File {
        val file = File.createTempFile("baseline", ".json")
        file.writeText(content)
        file.deleteOnExit()
        return file
    }
}
