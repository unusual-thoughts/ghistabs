package ghicpp.gui

import docking.action.builder.ActionBuilder
import docking.widgets.filechooser.GhidraFileChooser
import ghicpp.ooa.OoFactExporter
import ghidra.app.CorePluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.GoToService
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.util.Msg
import ghidra.util.task.TaskBuilder
import java.io.File

/** `Window > Class Hierarchy`: the class tree ([ClassTree]), over whichever source recorded the classes. */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Show and edit the C++ class hierarchy.",
    description = "Adds a 'Class Hierarchy' window: each C++ class under its namespace, expanding into its " +
        "direct bases and its members, or inverted into the classes derived from it. Classes come from the " +
        "class record the RTTI analyzers or another source (the stabs import) write, else from typeinfo, " +
        "vtables or namespaces alone.",
    servicesRequired = [GoToService::class],
)
class CppPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    private val tree = ClassTree(this)

    init {
        // `File > Export OOAnalyzer Facts...`: the program's object facts, for OOAnalyzer's Prolog rules.
        ActionBuilder("Export OOAnalyzer Facts", name)
            .menuPath("&File", "Export OOAnalyzer Facts...")
            .menuGroup("Export")
            .enabledWhen { currentProgram != null }
            .onAction { exportFacts() }
            .buildAndInstall(tool)
    }

    private fun exportFacts() {
        val program = currentProgram ?: return
        val chooser = GhidraFileChooser(tool.activeWindow).apply {
            setTitle("Export OOAnalyzer Facts")
            setSelectedFile(File(program.name.substringBeforeLast('.') + ".facts"))
        }
        val file = chooser.getSelectedFile(true).also { chooser.dispose() } ?: return
        TaskBuilder.withRunnable { monitor ->
            file.bufferedWriter().use { OoFactExporter(program, monitor).write(it) }
            Msg.info(this, "Wrote OOAnalyzer facts for ${program.name} to $file")
        }.setTitle("Export OOAnalyzer Facts").setCanCancel(true).launchModal()
    }

    override fun programActivated(program: Program) = tree.setProgram(program)

    override fun programDeactivated(program: Program) = tree.setProgram(null)

    override fun locationChanged(loc: ProgramLocation?) = tree.locationChanged(loc)

    override fun dispose() {
        tree.dispose()
        super.dispose()
    }
}
