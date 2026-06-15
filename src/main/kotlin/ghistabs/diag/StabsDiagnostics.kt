package ghistabs.diag

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghistabs.parser.GlobalTypeId
import ghistabs.parser.SourceFile

/**
 * Severity level for diagnostic output. Defaults to [INFO] at every callsite.
 */
enum class Level { DEBUG, INFO, WARN, ERROR }

/**
 * Narrow interface for diagnostic output (emits strings with a category tag).
 * Implemented by BookmarkSink, but also by test doubles for pure unit tests.
 *
 * [level] is an optional trailing argument so existing callsites stay valid;
 * only callers that care about severity need to pass it.
 */
interface DiagnosticSink {
    fun log(category: String, message: String? = null, level: Level = Level.INFO, address: Address? = null)
}

object DummySink : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?) {}
}

/**
 * Fan-out sink: each [log] call is delivered to every wrapped sink in order.
 * Used to tee Ghidra's truncating [MessageLog] alongside a test-side
 * [CapturingSink], so integration tests can read the full, non-truncated log
 * even when the analyzer is driven by `AutoAnalysisManager` (CONCURRENT mode).
 */
class TeeSink(private vararg val sinks: DiagnosticSink) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?) {
        for (s in sinks) s.log(category, message, level, address)
    }
}

fun MessageLog.toSink() = object : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?) {
        if (message == null) return
        val prefix = "[Stabs][${level.name}]"
        val line = if (address != null) "$prefix $category at $address: $message" else "$prefix $category: $message"
        if (level == Level.ERROR) appendMsg("ERROR: $line") else appendMsg(line)
    }
}

/**
 * GapRecord represents a gap between struct fields.
 * offsetBits: Position from struct start (in bits)
 * lengthBits: Size of gap (in bits)
 * prevField: Name of field before gap (null if first field)
 * nextField: Name of field after gap (null if trailing gap)
 */
data class GapRecord(val offsetBits: Long, val lengthBits: Long, val prevField: String?, val nextField: String?)

/**
 * AttributionTrace represents a decision to route a type to a /std/ category.
 * typeName: The name of the type being attributed.
 * definingCUs: All compilation units that define this type.
 * matchedCU: The specific CU that matched STD_MARKERS.
 * routedTo: The category path chosen (e.g., "/std/string").
 */
data class AttributionTrace(
    val typeName: String,
    val definingCUs: Set<SourceFile>,
    val matchedCU: SourceFile,
    val routedTo: String,
)

/**
 * Run-scoped diagnostic aggregator for the Stabs importer.
 * Records counters, examples, and structural gaps detected during analysis.
 *
 * Contract: After writeSummary() is called once, the instance becomes sealed.
 * Subsequent writeSummary() calls are no-ops and produce no output.
 * Counters remain readable via get() and snapshotCounters() after sealing.
 *
 * Thread safety: Not thread-safe. Caller must ensure single-threaded access.
 */
class StabsDiagnostics {
    private val counters: LinkedHashMap<String, Long> = linkedMapOf()
    private val examples: MutableMap<String, MutableList<String>> = linkedMapOf()
    private val gapCensus: MutableMap<String, List<GapRecord>> = linkedMapOf()
    private val attributionTraces: MutableList<AttributionTrace> = mutableListOf()

    private var isSealed = false

    /**
     * Increment a named counter by the given amount.
     * If the counter does not exist, it is created with value 0 before incrementing.
     */
    fun inc(name: String, by: Long = 1) {
        val current = counters.getOrDefault(name, 0L)
        counters[name] = current + by
    }

    /**
     * Get the current value of a named counter, or 0 if not present.
     */
    operator fun get(name: String): Long = counters.getOrDefault(name, 0L)

    /**
     * Return a snapshot of all counters in insertion order.
     */
    fun snapshotCounters(): Map<String, Long> = counters.toMap()

    /**
     * Record an example for a category, capping at 10 examples per category.
     */
    fun recordExample(category: String, msg: String) {
        val bucket = examples.getOrPut(category) { mutableListOf() }
        if (bucket.size < 10) {
            bucket.add(msg)
        }
    }

    /**
     * Record an unresolved type reference.
     * Increments "unresolved-ref" counter and records an example.
     */
    fun recordUnresolvedRef(refKey: GlobalTypeId?, referrer: String) {
        inc("unresolved-ref")
        recordExample("unresolved-ref", "ref=$refKey in $referrer")
    }

    /**
     * Record a placeholder type creation.
     * Increments "placeholder-created" counter and records an example.
     */
    fun recordPlaceholder(name: String, category: String, reason: String) {
        inc("placeholder-created")
        recordExample("placeholder-created", "name=$name category=$category reason=$reason")
    }

    /**
     * Record a deduplication decision (rename/merge/drop).
     * Increments the appropriate counter (e.g., "dedup-rename") and records an example.
     */
    fun recordDedup(kind: String, name: String, detail: String) {
        val counterName = "dedup-$kind"
        inc(counterName)
        recordExample(counterName, "name=$name detail=$detail")
    }

    /**
     * Record a vtable apply/skip/fail outcome.
     * Increments "vtable-applied", "vtable-skipped", or "vtable-failed" and records an example.
     */
    fun recordVtable(className: String, outcome: String, reason: String? = null) {
        val counterName = "vtable-$outcome"
        inc(counterName)
        val detail = if (reason != null) "class=$className reason=$reason" else "class=$className"
        recordExample(counterName, detail)
    }

    /**
     * Record an apply error during function analysis.
     * Increments "apply-error-$bucket" counter and records an example.
     */
    fun recordApplyError(funcName: String, bucket: String, detail: String) {
        val counterName = "apply-error-$bucket"
        inc(counterName)
        recordExample(counterName, "func=$funcName detail=$detail")
    }

    /**
     * Record an empty scope (locals list with no entries).
     * Increments "empty-scope" counter and records an example.
     */
    fun recordEmptyScope(addr: String, function: String?) {
        inc("empty-scope")
        val detail = if (function != null) "addr=$addr function=$function" else "addr=$addr"
        recordExample("empty-scope", detail)
    }

    /**
     * Record a global variable apply/skip outcome.
     * Increments "global-applied" or "global-skipped" and records an example.
     */
    fun recordGlobal(addr: String, outcome: String, dtKind: String, reason: String? = null) {
        val counterName = "global-$outcome"
        inc(counterName)
        val detail = if (reason != null) "addr=$addr dtKind=$dtKind reason=$reason" else "addr=$addr dtKind=$dtKind"
        recordExample(counterName, detail)
    }

    /**
     * Record gaps (holes) in a struct's field layout.
     * Only non-empty gap lists are stored; this effectively filters out fully-packed structs.
     */
    fun recordStructGaps(qualifiedName: String, gaps: List<GapRecord>) {
        if (gaps.isNotEmpty()) {
            gapCensus[qualifiedName] = gaps
        }
    }

    /**
     * Record an attribution trace and bump [counter]. Stores up to 200 traces
     * total across all buckets; further traces increment the counter only.
     */
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

    /**
     * Snapshot attribution traces for inspection.
     */
    fun snapshotAttributionTraces() = attributionTraces.toList()

    /**
     * Emit a complete diagnostic summary to the sink.
     *
     * Output format:
     * 1. Header line: "[Stabs] diagnostics: === diagnostics ==="
     * 2. Counter lines: "[Stabs] diagnostics: name = value" for each counter
     * 3. Example sections: "[Stabs] diagnostics: category top examples:" followed by indented lines
     * 4. Gap census section: per-struct gaps with offset/length and adjacent field names
     *
     * Idempotence contract: After the first call, subsequent calls are no-ops (sealed).
     * The sink receives output ONLY on the first call.
     */
    fun writeSummary(sink: DiagnosticSink) {
        if (isSealed) {
            return // Already emitted; suppress output
        }

        // Mark sealed before emitting so any re-entrant calls are suppressed
        isSealed = true

        // Emit header
        sink.log("diagnostics", "=== diagnostics ===")

        // Emit counters in insertion order
        for ((name, value) in counters) {
            sink.log("diagnostics", "$name = $value")
        }

        // Emit example buckets
        for ((category, msgs) in examples) {
            if (msgs.isNotEmpty()) {
                sink.log("diagnostics", "$category top examples:")
                for (msg in msgs) {
                    sink.log("diagnostics", "  - $msg")
                }
            }
        }

        // Emit gap census
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
