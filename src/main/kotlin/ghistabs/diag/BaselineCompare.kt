package ghistabs.diag

import java.io.File
import kotlin.math.ceil

/**
 * Utilities for comparing actual dangling-ref counts against baseline values.
 * Used by Phase 2 integration tests to verify >=90% reduction.
 */
object BaselineCompare {
    /**
     * Parses the dangling-ref baseline from a JSON file.
     * Expects: {"dangling-ref": <Long>}
     *
     * @throws IllegalArgumentException if the file does not contain a valid "dangling-ref" key
     */
    fun parseDanglingRefBaseline(file: File): Long {
        val content = file.readText()

        // Match "dangling-ref": <number> with optional whitespace
        val regex = """"dangling-ref"\s*:\s*(\d+)""".toRegex()
        val match =
            regex.find(content)
                ?: throw IllegalArgumentException(
                    "No valid 'dangling-ref' key found in baseline file: ${file.absolutePath}",
                )

        return match.groupValues[1].toLong()
    }

    /**
     * Checks if actual count passes a reduction threshold relative to baseline.
     * True iff actual <= ceil(baseline * ratio).
     * Default ratio is 0.10 for 90% reduction.
     *
     * Special case: if baseline is 0, returns true (no regression possible).
     */
    fun passesReduction(
        actual: Long,
        baseline: Long,
        ratio: Double = 0.10,
    ): Boolean {
        if (baseline == 0L) {
            return true
        }
        val threshold = ceil(baseline * ratio).toLong()
        return actual <= threshold
    }
}
