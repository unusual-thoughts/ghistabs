package ghistabs.baseline

import ghistabs.baseline.BaselineLoader
import ghistabs.baseline.CounterRange
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

// Pure unit test; lives outside `ghistabs.integration` so the `test` task (which path-excludes
// `**/integration/**` to avoid loading the headless-Ghidra base class) actually runs it.
class BaselineLoaderTest {
    @Test
    fun load_parsesCounterRanges(@TempDir tempDir: File) {
        val baselineFile = File(tempDir, "test-baseline.json").apply {
            writeText(
                """{
                        "counters": {
                            "local-var-error": {"min": 0, "max": 35},
                            "local-var-skipped-dup-param": {"min": 50, "max": 200}
                        }
                    }""",
            )
        }

        val baseline = BaselineLoader.load(baselineFile)

        assertEquals(2, baseline.counters.size)
        assertEquals(CounterRange(0, 35), baseline.counters["local-var-error"])
        assertEquals(CounterRange(50, 200), baseline.counters["local-var-skipped-dup-param"])
    }

    @Test
    fun load_parses_xapasmcsrBaseline() {
        val baselineFile = File("src/test/resources/baselines/xapasmcsr-baseline.json")
        assertTrue(baselineFile.exists(), "baseline file should exist")

        val baseline = BaselineLoader.load(baselineFile)

        // Mostly BaselineWriter point snapshots (min == max), but a counter with known runtime
        // nondeterminism may be hand-widened (xref-base-tag-resolved is [41..49] for CONCURRENT
        // demangler-order jitter). So assert well-formed ranges, not point ranges.
        assertTrue(baseline.counters.isNotEmpty())
        assertTrue(baseline.counters.containsKey("empty-scope"))
        assertTrue(baseline.counters.containsKey("harvest-records-read"))
        baseline.counters.forEach { (name, range) ->
            assertTrue(range.min <= range.max, "$name has an inverted range ${range.min}..${range.max}")
        }
    }

    @Test
    fun load_throwsOnMissingFile() {
        val missingFile = File("/nonexistent/baseline.json")

        val exception = try {
            BaselineLoader.load(missingFile)
            null
        } catch (e: IllegalArgumentException) {
            e
        }

        assertTrue(exception != null, "Should throw IllegalArgumentException for missing file")
    }
}
