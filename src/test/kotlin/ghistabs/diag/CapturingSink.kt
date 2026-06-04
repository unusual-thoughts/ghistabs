package ghistabs.diag

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.ConsoleTaskMonitor
import ghistabs.StabsOptions
import ghistabs.importer.ImportContext

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

    fun tagFrequencies(): Map<String, Long> = lines
        .groupingBy { it.tag }
        .eachCount()
        .mapValues { it.value.toLong() }
}

fun Program.defaultContext() = ImportContext(this, CapturingSink(), ConsoleTaskMonitor(), StabsOptions())
