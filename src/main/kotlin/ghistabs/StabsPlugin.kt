package ghistabs

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.widgets.filechooser.GhidraFileChooser
import docking.widgets.filechooser.GhidraFileChooserMode
import ghidra.app.CorePluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.task.Task
import ghidra.util.task.TaskLauncher
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DummySink
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.harvest.Harvester
import ghistabs.harvest.TypeResolver
import ghistabs.importer.ImportContext
import ghistabs.parse.StabReader
import ghistabs.render.Mode
import ghistabs.render.Renderer

/**
 * `Tools > Stabs` actions: **Re-import** clears the persistent done-flag and re-runs the
 * StabsAnalyzer; **Export decompilation…** reconstructs the per-source-file decompilation
 * (SjLj-elided) into a chosen folder — the same output the integration harness writes.
 */
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Re-run the STABS importer / export its decompilation on the current program.",
    description = "Adds 'Tools > Stabs > Re-import' (re-run the StabsAnalyzer) and " +
        "'Tools > Stabs > Export decompilation…' (write the reconstructed decompilation to a folder).",
)
class StabsPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    init {
        tool.addAction(action("Re-import", "&Re-import") { reimport(it) })
        tool.addAction(action("Export decompilation", "&Export decompilation…") { exportDecompilation(it) })
    }

    private fun action(id: String, menu: String, perform: (Program) -> Unit) =
        object : DockingAction("Stabs $id", getName()) {
            override fun actionPerformed(context: ActionContext?) {
                val program = currentProgram
                    ?: return Msg.showInfo(javaClass, null, "Stabs", "No program is open.")
                perform(program)
            }

            override fun isEnabledForContext(context: ActionContext?) = hasStabs()
        }.apply {
            menuBarData = MenuData(arrayOf("&Tools", "Stabs", menu), null, "Stabs")
            isEnabled = true
        }

    private fun hasStabs() =
        currentProgram?.memory?.getBlock(".stab") != null && currentProgram?.memory?.getBlock(".stabstr") != null

    private fun reimport(program: Program) {
        StabsAnalyzer.markStabsDone(program, false)
        AutoAnalysisManager.getAnalysisManager(program).reAnalyzeAll(null)
    }

    private fun exportDecompilation(program: Program) {
        // The reconstruction re-harvests the stabs cheaply, but the decompilation it renders is only
        // meaningful once the importer has applied types/locals to the program — require that first.
        if (!StabsAnalyzer.isStabsDone(program)) {
            return Msg.showInfo(
                javaClass,
                null,
                "Stabs",
                "Run the Stabs importer first (auto-analysis, or Tools > Stabs > Re-import).",
            )
        }
        val chooser = GhidraFileChooser(tool.activeWindow).apply {
            setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY)
            title = "Export decompilation to folder"
        }
        val dir = chooser.selectedFile
        chooser.dispose()
        if (dir == null) return
        TaskLauncher.launch(object : Task("Stabs: export decompilation", true, false, true) {
            override fun run(monitor: TaskMonitor) {
                val options = StabsOptions(program)
                val reader = StabReader.fromProgram(program) ?: return
                val harvest = program.runTransaction("stabs-export-harvest") {
                    Harvester(
                        ImportContext(
                            program,
                            monitor,
                            options,
                            terminal = DummySink,
                            diagnostics = StabsDiagnostics(),
                        ),
                    ).passA(reader.records)
                }
                val written = Renderer(
                    TypeResolver(harvest, canonicalizePaths = options.canonicalizePaths),
                    program,
                    Mode.ELIDE_SJLJ,
                ).use { it.renderAll(dir, monitor) }
                Msg.showInfo(javaClass, null, "Stabs", "Wrote $written decompilation files to $dir")
            }
        })
    }
}
