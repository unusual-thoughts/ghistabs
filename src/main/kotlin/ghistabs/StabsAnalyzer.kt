package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
class StabsAnalyzer : AbstractAnalyzer("My Analyzer", "Analyzer description goes here", AnalyzerType.BYTE_ANALYZER) {
    override fun getDefaultEnablement(program: Program?): Boolean {
        // Return true if analyzer should be enabled by default

        return true
    }

    override fun canAnalyze(program: Program?): Boolean {
        // Examine 'program' to determine of this analyzer should analyze it.  Return true
        // if it can.

        return true
    }

    override fun registerOptions(
        options: Options,
        program: Program?,
    ) {
        // If this analyzer has custom options, register them here

        options.registerOption(
            "Option name goes here",
            false,
            null,
            "Option description goes here",
        )
    }

    @Throws(CancelledException::class)
    override fun added(
        program: Program?,
        set: AddressSetView?,
        monitor: TaskMonitor?,
        log: MessageLog?,
    ): Boolean {
        // Perform analysis when things get added to the 'program'.  Return true if the
        // analysis succeeded.

        return false
    }
}
