package ghicpp.gui

import ghicpp.analyzers.GenericVftableAnalyzer
import ghicpp.analyzers.ItaniumClassAnalyzer
import ghicpp.analyzers.MethodClassAnalyzer
import ghicpp.analyzers.MsvcClassAnalyzer
import ghicpp.analyzers.RttiSymbolAnalyzer
import ghicpp.analyzers.TypeinfoLayoutAnalyzer
import ghicpp.analyzers.VirtualBaseAnalyzer
import ghicpp.analyzers.VtableSweepAnalyzer
import ghidra.app.services.Analyzer
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.Swing
import ghidra.util.exception.CancelledException
import ghidra.util.task.MonitoredRunnable
import ghidra.util.task.TaskLauncher
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.capturingReports
import ghidrakt.runTransaction

internal const val REANALYZE = "Reanalyze Classes"

/** The analyzers that build the class record and what hangs off it, in the order auto-analysis runs them. */
private fun classAnalyzers(): List<Analyzer> = listOf(
    RttiSymbolAnalyzer(),
    VtableSweepAnalyzer(),
    TypeinfoLayoutAnalyzer(),
    MsvcClassAnalyzer(),
    ItaniumClassAnalyzer(),
    VirtualBaseAnalyzer(),
    GenericVftableAnalyzer(),
    MethodClassAnalyzer(),
).sortedBy { it.priority.priority() }

/** Whether [a] is on for this program in Analysis Options, as auto-analysis would run it. */
private fun Program.isEnabled(a: Analyzer) =
    getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(a.name, a.getDefaultEnablement(this))

/** What one run of the class analyzers did, for the dialog that ends it. */
internal data class Reanalysis(
    // The analyzers that ran, by name, in order.
    val ran: List<String>,
    // What each of them reported doing, "<analyzer>: <what>".
    val reports: List<String>,
    // The warnings and errors they logged.
    val problems: String,
    val cancelled: Boolean = false,
    val failure: Throwable? = null,
) {
    /** The dialog's text: what each analyzer did, or that it found nothing to do, then what went wrong. */
    fun summary(): String = buildString {
        if (ran.isEmpty()) {
            append("No class analyzer applies to this program, or each is off in Analysis Options.")
        }
        for (name in ran) {
            val said = reports.filter { it.startsWith("$name: ") }.map { it.removePrefix("$name: ") }
            append("$name: ").append(said.ifEmpty { listOf("nothing to change") }.joinToString("; ")).append('\n')
        }
        if (cancelled) append("\nCancelled: what ran before then is kept.\n")
        failure?.let { append("\nFailed: ${it.message ?: it.javaClass.simpleName}\n") }
        problems.lines().filter(String::isNotBlank).takeIf { it.isNotEmpty() }?.let { lines ->
            append("\nWarnings (${lines.size}):\n")
            lines.take(MAX_PROBLEMS).forEach { append("  ").append(it).append('\n') }
            if (lines.size > MAX_PROBLEMS) append("  … ${lines.size - MAX_PROBLEMS} more in the log\n")
        }
    }.trimEnd()

    val isTrouble get() = failure != null || problems.isNotBlank()

    companion object {
        private const val MAX_PROBLEMS = 20
    }
}

/**
 * Runs again, over the whole program, each class analyzer that applies to it and is on, as Analysis > One Shot
 * would one by one, then says in a dialog what each did. The analyzers also log it, as in auto-analysis.
 */
internal fun Program.reanalyzeClasses(monitor: TaskMonitor): Reanalysis {
    val log = MessageLog()
    val ran = mutableListOf<String>()
    var cancelled = false
    var failure: Throwable? = null
    val (_, reports) = capturingReports {
        runTransaction(REANALYZE) {
            for (a in classAnalyzers().filter { it.canAnalyze(this) && isEnabled(it) }) {
                if (monitor.isCancelled) {
                    cancelled = true
                    break
                }
                monitor.setMessage(a.name)
                ran += a.name
                try {
                    a.added(this, memory, monitor, log)
                } catch (ignored: CancelledException) {
                    cancelled = true
                    break
                } catch (e: Exception) {
                    Msg.error(this, "${a.name} failed: ${e.message}", e)
                    failure = e
                    break
                }
            }
        }
    }
    return Reanalysis(ran, reports, log.toString(), cancelled, failure)
}

/** [reanalyzeClasses] in a task that can be cancelled, then its [Reanalysis.summary] in a dialog. */
internal fun ClassTree.reanalyzeClasses() {
    val p = program ?: return
    TaskLauncher.launchModal(
        REANALYZE,
        MonitoredRunnable { monitor ->
            val done = p.reanalyzeClasses(monitor)
            Swing.runLater {
                if (done.isTrouble) {
                    Msg.showWarn(this, component, REANALYZE, done.summary())
                } else {
                    Msg.showInfo(this, component, REANALYZE, done.summary())
                }
            }
        },
    )
}
