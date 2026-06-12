package ghistabs.diag

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.StabsOptions
import ghistabs.builder.TypeRegistry
import ghistabs.importer.ImportContext
import ghistabs.parser.Harvest

/**
 * Pure Kotlin test double that captures log() calls into a list.
 */
class CapturingSink : DiagnosticSink {
    data class LogLine(val tag: String, val address: Address?, val msg: String?) {
        override fun toString(): String = if (address != null) {
            "[$tag] at @$address $msg"
        } else {
            "[$tag] $msg"
        }
    }

    internal val lines = mutableListOf<LogLine>()

    override fun log(category: String, message: String?, address: Address?) {
        lines.add(LogLine(tag = category, msg = message, address = address))
    }

    fun capturedOutput(): String = lines.filter { it.msg != null }.joinToString("\n")

    /**
     * [capturedOutput] with repeated `(tag, msg)` pairs suppressed beyond
     * [maxPerKey] occurrences. Address-bearing lines are never dropped —
     * each address is a unique location. tagFrequencies stays raw so
     * counter-baseline assertions remain stable.
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

    fun tagFrequencies(): Map<String, Long> = lines
        .groupingBy { it.tag }
        .eachCount()
        .mapValues { it.value.toLong() }
}

fun Program.defaultContext() = ImportContext(this, CapturingSink(), TaskMonitor.DUMMY, StabsOptions())
fun ImportContext<*>.defaultTypeRegistry(): TypeRegistry {
    val harvest = Harvest(mapOf())
    return TypeRegistry(dtm, sink, diagnostics, harvest)
}
