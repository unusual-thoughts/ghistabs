package ghistabs.diagnose

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.harvest.Harvest
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.materialize.TypeRegistry

/**
 * Shared test diagnostics / dump infrastructure — the non-test scaffolding that captures import
 * output and serialises snapshots for inspection under `build/test-output/`. Kept out of the test
 * classes so they hold assertions only.
 */

/** Pure Kotlin test double that captures `log()` calls into a list. */
class CapturingSink : DiagnosticSink {
    data class LogLine(val tag: String, val address: Address?, val msg: String?, val level: Level = Level.INFO) {
        override fun toString(): String = if (address != null) {
            "[${level.name}][$tag] at @$address $msg"
        } else {
            "[${level.name}][$tag] $msg"
        }
    }

    internal val lines = mutableListOf<LogLine>()

    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        lines.add(LogLine(tag = category, msg = message, address = address, level = level))
    }

    fun capturedOutput(): String = lines.filter { it.msg != null }.joinToString("\n")

    /**
     * [capturedOutput] with repeated `(tag, msg)` pairs suppressed beyond [maxPerKey] occurrences.
     * Address-bearing lines are never dropped — each address is a unique location. tagFrequencies
     * stays raw so counter-baseline assertions remain stable.
     */
    fun dedupedOutput(maxPerKey: Int = 3): String {
        val seen = mutableMapOf<Pair<String, String?>, Int>()
        return buildString {
            for (line in lines) {
                if (line.msg == null) continue
                if (line.address != null) {
                    if (isNotEmpty()) append('\n')
                    append(line.toString())
                    continue
                }
                val key = line.tag to line.msg
                val count = (seen[key] ?: 0) + 1
                seen[key] = count
                when {
                    count <= maxPerKey -> {
                        if (isNotEmpty()) append('\n')
                        append(line.toString())
                    }

                    count == maxPerKey + 1 -> {
                        if (isNotEmpty()) append('\n')
                        append("[${line.tag}] ...suppressing further duplicates of: ${line.msg}")
                    }
                    // else silently drop
                }
            }
        }
    }
}

// Tests capture at max verbosity — DEBUG and up — so log assertions see every message.
fun Program.defaultContext() = ImportContext(
    this,
    TaskMonitor.DUMMY,
    // overlaySection off: the decoded-struct .stab overlay is a diagnostic view, not needed to produce
    // types, and it's ~8% of the run. StabSectionOverlayIntegrationTest exercises it directly.
    StabsOptions(minLogLevel = Level.DEBUG, overlaySection = false),
    CapturingSink(),
    StabsDiagnostics(),
)

fun ImportContext<*>.defaultTypeRegistry(): TypeRegistry {
    val harvest = Harvest(mapOf())
    return TypeRegistry(dtm, this, diagnostics, harvest, TypeResolver.Empty)
}
