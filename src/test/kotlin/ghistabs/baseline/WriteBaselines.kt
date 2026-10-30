package ghistabs.baseline

import ghistabs.integration.BASELINE_MODES
import java.io.File

/**
 * Writes baselines from what every mode of integrationTest observed ([Observations]), once all of them
 * have run: each fixture's committed baseline when [regenerate], else a shifted copy under [shiftedDir]
 * for each fixture whose counts left its committed ranges or gained a counter. A fixture with no
 * committed baseline gets one only when regenerating.
 */
fun writeBaselines(observedDir: File, baselinesDir: File, shiftedDir: File, regenerate: Boolean) {
    shiftedDir.deleteRecursively()
    val observations = Observations(observedDir)
    val modes = BASELINE_MODES.map { it.name }
    for (fixture in observations.fixtures()) {
        val observed = observations.load(fixture, modes)
        val counts = observed.map { o -> o.counters.mapValues { it.value.min } }
        val targets = observed.flatMap { it.counters.entries }
            .groupBy({ it.key }, { it.value.degrades })
            .mapValues { (_, lists) -> lists.flatten().distinct().sorted() }
        val binary = observed.first().source ?: fixture
        val committed = File(baselinesDir, "$fixture-baseline.json")
        val complete = observed.size == modes.size
        if (regenerate) {
            BaselineWriter.write(
                committed,
                counts,
                "$binary - generated from snapshotCounters()",
                committed,
                targets,
                complete,
            )
        } else if (committed.exists() && counts.any { it.shiftsFrom(BaselineLoader.load(committed)) }) {
            val shifted = File(shiftedDir, committed.name)
            BaselineWriter.write(shifted, counts, "$binary - shifted from committed", committed, targets, complete)
        }
    }
}

/** Whether these counts leave [baseline]'s ranges or hold a counter it lacks, as countersWithinBaseline checks. */
private fun Map<String, Long>.shiftsFrom(baseline: Baseline) =
    baseline.counters.any { (name, range) -> getOrDefault(name, 0L) !in range.min..range.max } ||
        (keys - baseline.counters.keys).isNotEmpty()

/** `observedDir baselinesDir shiftedDir regenerate`, as the writeBaselines task passes them. */
fun main(args: Array<String>) {
    val (observed, baselines, shifted, regenerate) = args
    writeBaselines(File(observed), File(baselines), File(shifted), regenerate == "true")
}
