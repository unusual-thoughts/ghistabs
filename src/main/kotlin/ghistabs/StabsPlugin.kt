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
import ghidra.util.HelpLocation
import ghidra.util.Msg
import ghistabs.ImportOptions.Companion.markStabsDone
import ghistabs.parse.StabReader

/**
 * `Tools > Stabs > Re-import`: clears the persistent done-flag and re-runs the StabsAnalyzer.
 * The render is exported through [StabsDecompExporter] (`File > Export Program…`), not from here.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Re-run the STABS importer on the current program.",
    description = "Adds 'Tools > Stabs > Re-import', which clears the 'Stabs Imported' flag and " +
        "re-runs auto-analysis so the StabsAnalyzer executes again.",
)
class StabsPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    init {
        tool.addAction(
            object : DockingAction("Stabs Re-import", getName()) {
                override fun actionPerformed(context: ActionContext?) {
                    val program = currentProgram
                        ?: return Msg.showInfo(javaClass, null, "Stabs", "No program is open.")
                    program.markStabsDone(false)
                    AutoAnalysisManager.getAnalysisManager(program).reAnalyzeAll(null)
                }

                override fun isEnabledForContext(context: ActionContext?) =
                    currentProgram?.let(StabReader::hasStabs) == true
            }.apply {
                menuBarData = MenuData(arrayOf("&Tools", "Stabs", "&Re-import"), null, "Stabs")
                // `src/main/help/help/topics/Stabs/` — the topic dir name is the topic id.
                helpLocation = HelpLocation("Stabs", "Stabs_Reimport")
                isEnabled = true
            },
        )
    }
}
