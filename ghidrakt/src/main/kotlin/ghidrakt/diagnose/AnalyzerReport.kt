package ghidrakt.diagnose

import ghidra.app.services.Analyzer
import ghidra.util.Msg

// What [report] says on this thread while [capturingReports] runs, for a caller to show the user.
private val captured = ThreadLocal<MutableList<String>?>()

/**
 * Says what an analyzer did, in the application log. An analyzer's MessageLog is for what went wrong:
 * when analysis ends, Ghidra shows anything in it in a "warnings/errors issued during analysis" dialog.
 * Inside [capturingReports] it is also kept, so that a run the user started from a window can say it there.
 */
fun Analyzer.report(message: String) {
    captured.get()?.add("$name: $message")
    Msg.info(this, "$name: $message")
}

/**
 * Runs [block], and gives what every analyzer it runs on this thread [report]ed, in order, besides the log.
 * Nested, each block keeps its own.
 */
fun <T> capturingReports(block: () -> T): Pair<T, List<String>> {
    val outer = captured.get()
    val mine = mutableListOf<String>()
    captured.set(mine)
    return try {
        block() to mine
    } finally {
        captured.set(outer)
    }
}
