package ghistabs

import ghidra.framework.options.OptionType
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

/**
 * Turn off every boolean analyzer option whose name contains one of `-PdisableAnalyzers=<a>,<b>`
 * (case-insensitive). Lets a probe be run twice against one fixture — once with an analyzer, once
 * without — and the two output trees diffed, with no recompile between them. Returns what it disabled.
 */
fun Program.disableAnalyzersFromProperty(): List<String> {
    val needles = System.getProperty("disableAnalyzers").orEmpty()
        .split(',').map(String::trim).filter(String::isNotEmpty)
    if (needles.isEmpty()) return emptyList()
    val analysis = getOptions(Program.ANALYSIS_PROPERTIES)
    val hits = analysis.optionNames.filter { name ->
        analysis.getType(name) == OptionType.BOOLEAN_TYPE && needles.any { name.contains(it, ignoreCase = true) }
    }
    runTransaction("disable-analyzers") { hits.forEach { analysis.setBoolean(it, false) } }
    return hits
}
