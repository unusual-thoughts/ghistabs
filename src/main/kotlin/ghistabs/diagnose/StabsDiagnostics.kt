package ghistabs.diagnose

import ghidra.program.model.address.Address
import ghistabs.parse.SourceFile

/** A gap between struct fields. `prev`/`next` are null at struct start/end. */
data class GapRecord(val offsetBits: Long, val lengthBits: Long, val prevField: String?, val nextField: String?)

/** Decision to route a type to `/std/`. */
data class AttributionTrace(
    val typeName: String,
    val definingCUs: Set<SourceFile>,
    val matchedCU: SourceFile,
    val routedTo: String,
)

/** A materialization fallback (Undefined4, dropped field, placeholder base, skipped vtable slot…). */
data class DegradationRecord(val category: String, val detail: String)

const val DEGRADED_PREFIX = "degraded-"

/**
 * Record a materialization degradation: a WARN log under `degraded-<category>` (surfaced live and
 * counted like anything else) that the [StabsDiagnostics] accumulator also files as a structured
 * [DegradationRecord] for the per-fixture dumps. [context] and [detail] are joined into the message.
 */
fun DiagnosticSink.degradation(category: String, context: String, detail: String? = null) =
    warn("$DEGRADED_PREFIX$category", if (detail != null) "$context :: $detail" else context)

/**
 * Per-run diagnostic aggregator — the accumulating [DiagnosticSink] terminal. Each [log] bumps the
 * category counter (by [count]) and, when a message is present, keeps it as a capped example for the
 * summary. Single-threaded. [writeSummary] is one-shot — subsequent calls no-op, counters stay readable.
 */
class StabsDiagnostics : DiagnosticSink {
    private val counters: MutableMap<String, MutableMap<Level, Long>> = linkedMapOf()
    private val examples: MutableMap<String, MutableList<String>> = linkedMapOf()
    private val gapCensus: MutableMap<String, List<GapRecord>> = linkedMapOf()
    private val attributionTraces: MutableList<AttributionTrace> = mutableListOf()
    private val degradations: MutableList<DegradationRecord> = mutableListOf()

    private var isSealed = false

    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        inc(category, level, count)
        if (message != null) {
            recordExample(category, message)
            if (category.startsWith(DEGRADED_PREFIX)) {
                degradations.add(DegradationRecord(category.removePrefix(DEGRADED_PREFIX), message))
            }
        }
    }

    private fun inc(name: String, level: Level, by: Long = 1) {
        counters.getOrPut(name) { mutableMapOf() }.compute(level) { _, lng -> (lng ?: 0) + by }
    }

    /** How often the category fired, at any level — the level is a reporting attribute, not identity. */
    operator fun get(name: String): Long = counters[name]?.values?.sum() ?: 0L

    operator fun get(name: String, level: Level): Long = counters[name]?.get(level) ?: 0L

    fun snapshotCounters(): Map<String, Long> = counters.mapValues { it.value.values.sum() }

    /** Backing store for [log]'s example capture — capped at 10/category. */
    private fun recordExample(category: String, msg: String) {
        val bucket = examples.getOrPut(category) { mutableListOf() }
        if (bucket.size < 10) {
            bucket.add(msg)
        }
    }

    fun recordStructGaps(qualifiedName: String, gaps: List<GapRecord>) {
        if (gaps.isNotEmpty()) {
            gapCensus[qualifiedName] = gaps
        }
    }

    /** Stores up to 200 traces total across all buckets; beyond that only the counter bumps. */
    fun recordAttributionTrace(
        typeName: String,
        definingCUs: Set<SourceFile>,
        matchedCU: SourceFile,
        routedTo: String,
        counter: String,
    ) {
        if (attributionTraces.size < 200) {
            attributionTraces.add(
                AttributionTrace(
                    typeName = typeName,
                    definingCUs = definingCUs,
                    matchedCU = matchedCU,
                    routedTo = routedTo,
                ),
            )
        }
        inc(counter, Level.DEBUG)
    }

    fun snapshotAttributionTraces() = attributionTraces.toList()

    /** Structured degradations, filed by [log] when it sees a `degraded-` category (see [degradation]). */
    fun snapshotDegradations(): List<DegradationRecord> = degradations.toList()

    /** One-shot — subsequent calls are no-ops. Emits counters, example buckets, and gap census. */
    fun writeSummary(sink: DiagnosticSink) {
        if (isSealed) {
            return
        }
        isSealed = true

        sink.debug(
            "diagnostics",
            buildString {
                appendLine("=== Summary of diagnostic categories ===")
                for ((name, levels) in counters) {
                    for ((level, value) in levels) {
                        appendLine("$name = $value") // level)
                    }
                }
            }.trimEnd(),
        )

        for ((category, msgs) in examples) {
            if (msgs.isNotEmpty()) {
                sink.debug(
                    "diagnostics",
                    buildString {
                        appendLine("$category top examples:")
                        for (msg in msgs) {
                            appendLine("  - $msg")
                        }
                    }.trimEnd(),
                )
            }
        }

        sink.debug(
            "diagnostics",
            buildString {
                if (gapCensus.isNotEmpty()) {
                    appendLine("=== gap census ===")
                    for ((qualifiedName, gaps) in gapCensus) {
                        for ((offsetBits, lengthBits, prevField, nextField) in gaps) {
                            val prevStr = prevField ?: "(start)"
                            val nextStr = nextField ?: "(end)"
                            appendLine(
                                "  $qualifiedName: gap @+$offsetBits bits len=$lengthBits between $prevStr..$nextStr",
                            )
                        }
                    }
                }
            }.trimEnd(),
        )
    }
}
