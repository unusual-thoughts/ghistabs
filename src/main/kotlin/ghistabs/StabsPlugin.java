package ghistabs;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.main.AnalyzerPluginPackage;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Adds a 'Tools > Stabs > Re-import' action that clears the persistent done-flag
 * and re-runs the StabsAnalyzer on the current program.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = AnalyzerPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Re-run the STABS importer on the current program.",
    description = "Adds a 'Tools > Stabs > Re-import' action that clears the persistent done-flag and re-runs the StabsAnalyzer."
)
public class StabsPlugin extends ProgramPlugin {

    public StabsPlugin(PluginTool tool) {
        super(tool);
        DockingAction reimport = new DockingAction("Stabs Re-import", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Program program = getCurrentProgram();
                if (program == null) {
                    Msg.showInfo(getClass(), null, "Stabs Re-import", "No program is open.");
                    return;
                }
                int tx = program.startTransaction("Stabs: clear done flag (re-import)");
                try {
                    program.getOptions(Program.PROGRAM_INFO)
                        .setBoolean(StabsAnalyzer.STABS_DONE_OPTION, false);
                } finally {
                    program.endTransaction(tx, true);
                }
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                StabsAnalyzer analyzer = new StabsAnalyzer();
                mgr.scheduleOneTimeAnalysis(analyzer, program.getMemory());
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                Program p = getCurrentProgram();
                if (p == null) return false;
                return p.getMemory().getBlock(".stab") != null
                    && p.getMemory().getBlock(".stabstr") != null;
            }
        };
        reimport.setMenuBarData(new MenuData(new String[] { "&Tools", "Stabs", "&Re-import" }, null, "Stabs"));
        reimport.setEnabled(true);
        tool.addAction(reimport);
    }
}
