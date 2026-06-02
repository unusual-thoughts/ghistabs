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
    internal val lines = mutableListOf<Triple<String, Address?, String>>()

    override fun log(category: String, message: String, address: Address?) {
        lines.add(Triple(category, address, message))
    }

    fun capturedOutput(): String = lines.joinToString("\n") { (category, addr, msg) ->
        if (addr != null) {
            "[$category] at @addr $msg"
        } else {
            "[$category] $msg"
        }
    }

    fun tagFrequencies(): Map<String, Long> = lines
        .groupingBy { it.first }
        .eachCount()
        .mapValues { it.value.toLong() }
}

fun Program.defaultContext() = ImportContext(this, CapturingSink(), ConsoleTaskMonitor(), StabsOptions())
