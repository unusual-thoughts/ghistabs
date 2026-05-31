package ghistabs.integration

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class BaselineLoaderTest {
    @Test
    fun load_parsesCounterRanges(
        @TempDir tempDir: File,
    ) {
        val baselineFile =
            File(tempDir, "test-baseline.json").apply {
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
    fun load_parses_bouniafbouniafBaseline() {
        val baselineFile = File("src/test/resources/baselines/bouniafbouniaf-baseline.json")
        assertTrue(baselineFile.exists(), "baseline file should exist")

        val baseline = BaselineLoader.load(baselineFile)

        // Verify known counters are present
        assertTrue(baseline.counters.containsKey("local-var-error"))
        assertTrue(baseline.counters.containsKey("local-var-skipped-dup-param"))
        assertTrue(baseline.counters.containsKey("empty-scope"))

        // Verify a few known ranges
        assertEquals(CounterRange(0, 35), baseline.counters["local-var-error"])
        assertEquals(CounterRange(0, 0), baseline.counters["empty-scope"])
    }

    @Test
    fun load_throwsOnMissingFile() {
        val missingFile = File("/nonexistent/baseline.json")

        val exception =
            try {
                BaselineLoader.load(missingFile)
                null
            } catch (e: IllegalArgumentException) {
                e
            }

        assertTrue(exception != null, "Should throw IllegalArgumentException for missing file")
    }
}
