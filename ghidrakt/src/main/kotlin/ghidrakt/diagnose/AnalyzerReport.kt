package ghidrakt.diagnose

import ghidra.app.services.Analyzer
import ghidra.util.Msg

/**
 * Says what an analyzer did, in the application log. An analyzer's MessageLog is for what went wrong:
 * when analysis ends, Ghidra shows anything in it in a "warnings/errors issued during analysis" dialog.
 */
fun Analyzer.report(message: String) = Msg.info(this, "$name: $message")
