package ghistabs.baseline

import ghistabs.test.must
import ghistabs.test.mustBe
import ghistabs.test.mustNotBeEmpty
import ghistabs.test.mustNotBeNull
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

        baseline.counters.size mustBe 2
        baseline.counters["local-var-error"] mustBe CounterRange(0, 35)
        baseline.counters["local-var-skipped-dup-param"] mustBe CounterRange(50, 200)
    }

    /** Every committed baseline, so a hand-edit that inverts a range fails here and not mid-import. */
    @Test
    fun load_parsesEveryCommittedBaseline() {
        val baselines = File("src/test/resources/baselines").listFiles { f: File ->
            f.extension == "json"
        }.orEmpty().toList()
        baselines.mustNotBeEmpty("no committed baselines to load")

        baselines.forEach { file ->
            val baseline = BaselineLoader.load(file)
            baseline.counters.mustNotBeEmpty("${file.name} parsed to no counters")
            // Mostly BaselineWriter point snapshots (min == max), but a counter with known runtime
            // nondeterminism may be hand-widened (xref-base-tag-resolved is [41..49] for CONCURRENT
            // demangler-order jitter). So assert well-formed ranges, not point ranges.
            baseline.counters.forEach { (name, range) ->
                range.must("${file.name}: $name has an inverted range ${range.min}..${range.max}") { min <= max }
            }
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
        exception.mustNotBeNull("Should throw IllegalArgumentException for missing file")
    }
}
