package ghistabs

import ghidra.program.model.listing.Program

/**
 * Disable WindowsResourceReferenceAnalyzer before autoanalysis. On PE binaries it runs a Ghidra script
 * (findScriptByName → GhidraScriptUtil.getScriptSourceDirectories), which NPEs under the test harness —
 * there's no OSGi bundle host and no user-settings dir to start one. It's irrelevant to stabs import, so
 * turn it off. Opens its own transaction.
 */
fun Program.disableWindowsResourceAnalyzer() = runTransaction("disable-windows-resource-analyzer") {
    getOptions(Program.ANALYSIS_PROPERTIES).setBoolean("WindowsResourceReference", false)
}
