package ghistabs.baseline

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption

@Serializable
data class CounterRange(
    val min: Long,
    val max: Long,
    /**
     * For a counter that degrades something, the distinct things it degraded, sorted. A count says a
     * fixture got worse; this says *what* got worse, which is the question a drifted baseline raises.
     * Empty for counters that only tally.
     */
    val degrades: List<String> = emptyList(),
)

/**
 * Acceptable counter ranges loaded from a baseline JSON file.
 *
 * Schema (other top-level keys like `schema`, `source`, `phaseA`, `notes` are
 * accepted and ignored — they're documentation, not gates):
 * ```
 * {
 *   "counters": {
 *     "counter-name": {"min": 0, "max": 100, "degrades": ["Foo::bar", "Baz"]},
 *     ...
 *   }
 * }
 * ```
 */
@Serializable
data class Baseline(
    val counters: Map<String, CounterRange> = emptyMap(),
    // Tolerated-but-unused metadata; declared so kotlinx.serialization doesn't reject the doc.
    val schema: Int? = null,
    val source: String? = null,
    val phaseA: JsonElement? = null,
    val notes: String? = null,
)

object BaselineLoader {
    private val json = Json {
        ignoreUnknownKeys = true
    }

    fun load(file: File): Baseline {
        require(file.exists()) { "Baseline file not found: ${file.path}" }
        return json.decodeFromString(Baseline.serializer(), file.readText())
    }
}

object BaselineWriter {
    private val json = Json {
        prettyPrint = true
        prettyPrintIndent = "    "
        encodeDefaults = false
    }

    /**
     * Overwrite [file] with a snapshot of [counters] (min == max == observed). Regenerate after an
     * intentional counter change; the git diff of the baseline is then the record of exactly which
     * counts moved. A counter that carries an intentional `min < max` range in [priorFile] keeps it as
     * long as the observed value still falls inside it.
     */
    fun write(
        file: File,
        counters: Map<String, Long>,
        source: String,
        priorFile: File = file,
        degradationTargets: Map<String, List<String>> = emptyMap(),
    ) = write(file, listOf(counters), source, priorFile, degradationTargets, complete = true)

    /**
     * Overwrite [file] with one range per counter over every run mode's [observed] counts, so the file
     * is the same whichever mode finished last. The import is deterministic per run mode, but some
     * counters differ between the CONCURRENT and AFTER modes the suite checks; a counter one mode never
     * reports counts 0 there. [complete] says whether [observed] holds every checked mode: when it does
     * not, the [priorFile] ranges are widened rather than replaced, since a mode that has not run yet
     * may still need them. Either way a prior `min < max` range that holds every observation is kept.
     */
    fun write(
        file: File,
        observed: List<Map<String, Long>>,
        source: String,
        priorFile: File?,
        degradationTargets: Map<String, List<String>>,
        complete: Boolean,
    ) {
        val prior = if (priorFile?.exists() == true) {
            runCatching { BaselineLoader.load(priorFile).counters }.getOrDefault(emptyMap())
        } else {
            emptyMap()
        }
        val names = observed.flatMapTo(sortedSetOf()) { it.keys }.apply { if (!complete) addAll(prior.keys) }
        val baseline = Baseline(
            source = source,
            counters = names.associateWith { name ->
                val seen = observed.map { it[name] ?: 0L }
                val was = prior[name]
                val range = when {
                    seen.isEmpty() -> was!!
                    was != null && was.min < was.max && seen.all { it in was.min..was.max } -> was
                    was != null && !complete -> CounterRange(minOf(seen.min(), was.min), maxOf(seen.max(), was.max))
                    else -> CounterRange(seen.min(), seen.max())
                }
                range.copy(degrades = degradationTargets[name].orEmpty())
            },
        )
        file.parentFile?.mkdirs()
        file.writeText(json.encodeToString(Baseline.serializer(), baseline) + "\n")
    }
}

/**
 * What one run mode of a fixture observed, kept beside the other modes' so a baseline written from
 * them covers every mode ([BaselineWriter.write]) instead of whichever ran last.
 */
class Observations(private val dir: File, private val fixture: String) {
    private fun file(mode: String) = File(dir, "$fixture.$mode.json")

    /**
     * Run [block] holding this fixture's lock: modes run in parallel forks, and one that read the others'
     * observations before another recorded its own would otherwise write a baseline missing it, last.
     */
    fun <T> locked(block: () -> T): T {
        dir.mkdirs()
        val lock = File(dir, "$fixture.lock").toPath()
        return FileChannel.open(lock, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
            .use { channel -> channel.lock().use { block() } }
    }

    fun record(mode: String, counters: Map<String, Long>, degradationTargets: Map<String, List<String>>) =
        BaselineWriter.write(file(mode), listOf(counters), "observed", null, degradationTargets, complete = true)

    /** The counters each of [modes] recorded, in [modes] order, and whether every one of them has. */
    fun load(modes: Collection<String>): Pair<List<Map<String, Long>>, Boolean> {
        val seen = modes.filter { file(it).exists() }
        val counters = seen.map { m -> BaselineLoader.load(file(m)).counters.mapValues { it.value.min } }
        return counters to (seen.size == modes.size)
    }

    /** The union of every recorded mode's degradation targets, per counter. */
    fun degradationTargets(modes: Collection<String>): Map<String, List<String>> = modes
        .filter { file(it).exists() }
        .flatMap { m -> BaselineLoader.load(file(m)).counters.entries }
        .groupBy({ it.key }, { it.value.degrades })
        .mapValues { (_, lists) -> lists.flatten().distinct().sorted() }
}
