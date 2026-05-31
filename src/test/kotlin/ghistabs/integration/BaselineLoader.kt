package ghistabs.integration

import java.io.File

/**
 * Represents a range of acceptable values for a counter.
 */
data class CounterRange(
    val min: Long,
    val max: Long,
)

/**
 * Represents a loaded baseline with counter ranges.
 */
data class Baseline(
    val counters: Map<String, CounterRange>,
)

/**
 * Loads and parses a baseline JSON file.
 * JSON structure:
 * {
 *   "counters": {
 *     "counter-name": {"min": 0, "max": 100},
 *     ...
 *   }
 * }
 */
object BaselineLoader {
    fun load(file: File): Baseline {
        require(file.exists()) { "Baseline file not found: ${file.path}" }

        val json = file.readText()

        // Simple regex-based JSON parsing to avoid external JSON dependency.
        // Extract all counter blocks matching pattern: "counter-name": {"min": N, "max": M}
        val counters = mutableMapOf<String, CounterRange>()

        // Match: "name": {"min": X, "max": Y}
        val pattern = """"([A-Za-z0-9._-]+)":\s*\{\s*"min":\s*(\d+),\s*"max":\s*(\d+)\s*\}""".toRegex()

        for (match in pattern.findAll(json)) {
            val name = match.groupValues[1]
            val min = match.groupValues[2].toLong()
            val max = match.groupValues[3].toLong()
            counters[name] = CounterRange(min, max)
        }

        return Baseline(counters)
    }
}
