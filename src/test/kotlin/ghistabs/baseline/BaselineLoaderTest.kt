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

    private fun baselineOf(dir: File, name: String, vararg ranges: Pair<String, CounterRange>) = File(dir, name).apply {
        val body = ranges.joinToString(",") { (k, r) -> """"$k": {"min": ${r.min}, "max": ${r.max}}""" }
        writeText("""{"counters": {$body}}""")
    }

    /** A deliberate tolerance range survives a regen that lands inside it — see [BaselineWriter.write]. */
    @Test
    fun write_keepsAToleranceRangeTheObservationFallsInside(@TempDir tempDir: File) {
        val file = baselineOf(tempDir, "b.json", "text-undisassembled-code" to CounterRange(3269, 3336))

        BaselineWriter.write(file, mapOf("text-undisassembled-code" to 3269L), "regen")

        BaselineLoader.load(file).counters["text-undisassembled-code"] mustBe CounterRange(3269, 3336)
    }

    /** …but an observation outside it means the range is stale, so it is pinned to what was seen. */
    @Test
    fun write_pinsARangeTheObservationFallsOutside(@TempDir tempDir: File) {
        val file = baselineOf(tempDir, "b.json", "replaced-demangler" to CounterRange(799, 800))

        BaselineWriter.write(file, mapOf("replaced-demangler" to 782L), "regen")

        BaselineLoader.load(file).counters["replaced-demangler"] mustBe CounterRange(782, 782)
    }

    /**
     * The shifted-baselines path: written to a file that does not exist yet, so the ranges have to be
     * read from the committed baseline instead. Without [priorFile] every counter regenerated as a
     * point, which silently un-widened the flaky ones on every CI run that published a shift.
     */
    @Test
    fun write_readsRangesFromPriorFileWhenWritingElsewhere(@TempDir tempDir: File) {
        val committed = baselineOf(tempDir, "committed.json", "text-data-no-coverage" to CounterRange(316, 356))
        val shifted = File(tempDir, "shifted/b.json").apply { parentFile.mkdirs() }

        BaselineWriter.write(shifted, mapOf("text-data-no-coverage" to 356L), "shifted", committed)

        BaselineLoader.load(shifted).counters["text-data-no-coverage"] mustBe CounterRange(316, 356)
    }
}
