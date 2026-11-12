package ghicpp.gui

import ghidra.app.CorePluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.GoToService
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation

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

    override fun programActivated(program: Program) = tree.setProgram(program)

    override fun programDeactivated(program: Program) = tree.setProgram(null)

    override fun locationChanged(loc: ProgramLocation?) = tree.locationChanged(loc)

    override fun dispose() {
        tree.dispose()
        super.dispose()
    }
}
