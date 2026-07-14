package ghistabs.baseline

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import java.io.File

@Serializable
data class CounterRange(val min: Long, val max: Long)

/**
 * Acceptable counter ranges loaded from a baseline JSON file.
 *
 * Schema (other top-level keys like `schema`, `source`, `phaseA`, `notes` are
 * accepted and ignored — they're documentation, not gates):
 * ```
 * {
 *   "counters": {
 *     "counter-name": {"min": 0, "max": 100},
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
     * Overwrite [file] with an exact snapshot of [counters] (min == max == observed — the import is
     * deterministic across run modes). Regenerate after an intentional counter change; the git diff
     * of the baseline is then the record of exactly which counts moved.
     */
    fun write(file: File, counters: Map<String, Long>, source: String) {
        val baseline = Baseline(
            source = source,
            counters = counters.toSortedMap().mapValues { (_, v) -> CounterRange(v, v) },
        )
        file.writeText(json.encodeToString(Baseline.serializer(), baseline) + "\n")
    }
}
