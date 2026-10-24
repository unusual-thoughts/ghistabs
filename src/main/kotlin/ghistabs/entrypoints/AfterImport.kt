package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.isAnalyzerEnabled
import ghistabs.runTransaction

/**
 * The analyzers that read what a stabs import applied, in their analysis order: auto-analysis runs them
 * after the Stabs Importer by priority. The import runs none of them itself.
 */
private fun afterImport(): List<AbstractAnalyzer> =
    listOf(SjljContextAnalyzer(), RttiLayoutAnalyzer(), GccVftableAnalyzer(), VirtualBaseAnalyzer())

/**
 * Run [afterImport]'s analyzers on the whole program, each that is on and takes it, as auto-analysis
 * would after the import: for a caller that imports outside auto-analysis (the cli, the tests).
 */
fun Program.analyzeAfterImport(monitor: TaskMonitor = TaskMonitor.DUMMY, log: MessageLog = MessageLog()) =
    runTransaction("Stabs: analyze after import") {
        for (analyzer in afterImport()) {
            if (isAnalyzerEnabled(analyzer.name) && analyzer.canAnalyze(this)) {
                analyzer.added(this, memory, monitor, log)
            }
        }
    }
