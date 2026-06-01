package ghistabs

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import ghidra.app.CorePluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import ghidra.util.Msg

/**
 * Adds a 'Tools > Stabs > Re-import' action that clears the persistent done-flag
 * and re-runs the StabsAnalyzer on the current program.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Re-run the STABS importer on the current program.",
    description = "Adds a 'Tools > Stabs > Re-import' action" +
        "that clears the persistent done-flag and re-runs the StabsAnalyzer.",
)
class StabsPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    init {
        val reimport = object : DockingAction("Stabs Re-import", getName()) {
            override fun actionPerformed(context: ActionContext?) {
                val program = getCurrentProgram()
                if (program == null) {
                    Msg.showInfo(javaClass, null, "Stabs Re-import", "No program is open.")
                    return
                }
                val tx = program.startTransaction("Stabs: clear done flag (re-import)")
                try {
                    program
                        .getOptions(Program.PROGRAM_INFO)
                        .setBoolean(StabsAnalyzer.STABS_DONE_OPTION, false)
                } finally {
                    program.endTransaction(tx, true)
                }
                val mgr: AutoAnalysisManager = AutoAnalysisManager.getAnalysisManager(program)
                mgr.reAnalyzeAll(null)
            }

            override fun isEnabledForContext(context: ActionContext?): Boolean {
                val p = getCurrentProgram() ?: return false
                return p.memory.getBlock(".stab") != null &&
                    p.memory.getBlock(".stabstr") != null
            }
        }
        reimport.menuBarData = MenuData(arrayOf("&Tools", "Stabs", "&Re-import"), null, "Stabs")
        reimport.isEnabled = true
        tool.addAction(reimport)
    }
}
