package ghistabs.diagnose

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile

enum class Level { DEBUG, INFO, WARN, ERROR }

/**
 * A diagnostic event. [count] lets one call stand in for a bulk tally (`log(cat, count = n)`
 * replaces the old `inc(cat, n)`); [message] null means a silent counter bump (no output).
 */
interface DiagnosticSink {
    fun log(
        category: String,
        message: String? = null,
        level: Level = Level.INFO,
        address: Address? = null,
        count: Long = 1,
    )
}

object DummySink : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {}
}

/** Fan-out sink — tees the [StabsDiagnostics] accumulator alongside a terminal (Bookmark/Capturing). */
class TeeSink(private vararg val sinks: DiagnosticSink) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        for (s in sinks) s.log(category, message, level, address, count)
    }
}

fun MessageLog.toSink() = object : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message == null) return
        val prefix = "[Stabs][${level.name}]"
        val line = if (address != null) "$prefix $category at $address: $message" else "$prefix $category: $message"
        if (level == Level.ERROR) appendMsg("ERROR: $line") else appendMsg(line)
    }
}

/** A gap between struct fields. `prev`/`next` are null at struct start/end. */
data class GapRecord(val offsetBits: Long, val lengthBits: Long, val prevField: String?, val nextField: String?)

/** Decision to route a type to `/std/`. */
data class AttributionTrace(
    val typeName: String,
    val definingCUs: Set<SourceFile>,
    val matchedCU: SourceFile,
    val routedTo: String,
)

/** A materialisation fallback (Undefined4, dropped field, placeholder base, skipped vtable slot…). */
data class DegradationRecord(val category: String, val context: String, val detail: String? = null)

/**
 * Per-run diagnostic aggregator — the accumulating [DiagnosticSink] terminal. Each [log] bumps the
 * category counter (by [count]) and, when a message is present, keeps it as a capped example for the
 * summary. Single-threaded. [writeSummary] is one-shot — subsequent calls no-op, counters stay readable.
 */
class StabsDiagnostics : DiagnosticSink {
    private val counters: LinkedHashMap<String, Long> = linkedMapOf()
    private val examples: MutableMap<String, MutableList<String>> = linkedMapOf()
    private val gapCensus: MutableMap<String, List<GapRecord>> = linkedMapOf()
    private val attributionTraces: MutableList<AttributionTrace> = mutableListOf()
    private val degradations: MutableList<DegradationRecord> = mutableListOf()

    private var isSealed = false

    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        inc(category, count)
        if (message != null) recordExample(category, message)
    }

    private fun inc(name: String, by: Long = 1) {
        val current = counters.getOrDefault(name, 0L)
        counters[name] = current + by
    }

    operator fun get(name: String): Long = counters.getOrDefault(name, 0L)

    fun snapshotCounters(): Map<String, Long> = counters.toMap()

    /** Record an example for [category], capped at 10/category. */
    fun recordExample(category: String, msg: String) {
        val bucket = examples.getOrPut(category) { mutableListOf() }
        if (bucket.size < 10) {
            bucket.add(msg)
        }
    }

    fun recordUnresolvedRef(refKey: GlobalTypeId?, referrer: String) {
        inc("unresolved-ref")
        recordExample("unresolved-ref", "ref=$refKey in $referrer")
    }

    fun recordPlaceholder(name: String, category: String, reason: String) {
        inc("placeholder-created")
        recordExample("placeholder-created", "name=$name category=$category reason=$reason")
    }

    fun recordVtable(className: String, outcome: String, reason: String? = null) {
        val counterName = "vtable-$outcome"
        inc(counterName)
        val detail = if (reason != null) "class=$className reason=$reason" else "class=$className"
        recordExample(counterName, detail)
        if (outcome == "failed") {
            recordDegradation("vtable-failed", className, reason)
        }
    }

    fun recordApplyError(funcName: String, bucket: String, detail: String) {
        val counterName = "apply-error-$bucket"
        inc(counterName)
        recordExample(counterName, "func=$funcName detail=$detail")
    }

    fun recordEmptyScope(addr: String, function: String?) {
        inc("empty-scope")
        val detail = if (function != null) "addr=$addr function=$function" else "addr=$addr"
        recordExample("empty-scope", detail)
    }

    fun recordGlobal(addr: String, outcome: String, dtKind: String, reason: String? = null) {
        val counterName = "global-$outcome"
        inc(counterName)
        val detail = if (reason != null) "addr=$addr dtKind=$dtKind reason=$reason" else "addr=$addr dtKind=$dtKind"
        recordExample(counterName, detail)
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
        inc(counter)
    }

    fun snapshotAttributionTraces() = attributionTraces.toList()

    /** Unbounded record; also bumps `degraded-$category` for the summary totals. */
    fun recordDegradation(category: String, context: String, detail: String? = null) {
        degradations.add(DegradationRecord(category, context, detail))
        inc("degraded-$category")
    }

    fun snapshotDegradations(): List<DegradationRecord> = degradations.toList()

    /** Caller gates this on the `logDegradations` analyzer option. */
    fun writeDegradations(sink: DiagnosticSink) {
        if (degradations.isEmpty()) return
        sink.log("degradations", "=== degradations (${degradations.size}) ===")
        for (d in degradations) {
            val msg = if (d.detail != null) "${d.context} :: ${d.detail}" else d.context
            sink.log(d.category, msg)
        }
    }

    /** One-shot — subsequent calls are no-ops. Emits counters, example buckets, and gap census. */
    fun writeSummary(sink: DiagnosticSink) {
        if (isSealed) {
            return
        }
        isSealed = true

        sink.log("diagnostics", "=== diagnostics ===")

        for ((name, value) in counters) {
            sink.log("diagnostics", "$name = $value")
        }

        for ((category, msgs) in examples) {
            if (msgs.isNotEmpty()) {
                sink.log("diagnostics", "$category top examples:")
                for (msg in msgs) {
                    sink.log("diagnostics", "  - $msg")
                }
            }
        }

        if (gapCensus.isNotEmpty()) {
            sink.log("diagnostics", "gap census:")
            for ((qualifiedName, gaps) in gapCensus) {
                for (gap in gaps) {
                    val prevStr = gap.prevField ?: "(start)"
                    val nextStr = gap.nextField ?: "(end)"
                    sink.log(
                        "diagnostics",
                        "  $qualifiedName: gap @+${gap.offsetBits} bits len=${gap.lengthBits} between $prevStr..$nextStr",
                    )
                }
            }
        }
    }
}
