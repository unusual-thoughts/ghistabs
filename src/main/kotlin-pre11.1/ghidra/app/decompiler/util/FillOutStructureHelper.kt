package ghidra.app.decompiler.util

import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighVariable
import ghidra.util.task.TaskMonitor

/**
 * Pre-11.1: Auto Fill in Structure's engine is still `FillOutStructureCmd`'s own, which 11 moved out into this
 * helper. The same calls, on the command, whose [processStructure] always fills a new structure.
 */
@Suppress("UNUSED_PARAMETER")
class FillOutStructureHelper(program: Program, monitor: TaskMonitor) {
    private val cmd = FillOutStructureCmd(program, null, null)

    fun processStructure(
        variable: HighVariable,
        function: Function,
        createNewStructure: Boolean,
        createClassIfNeeded: Boolean,
        decomplib: DecompInterface?,
    ) = cmd.processStructure(variable, function)

    val componentMap get() = cmd.componentMap
    val storePcodeOps get() = cmd.storePcodeOps
}
