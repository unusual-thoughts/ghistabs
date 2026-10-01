package ghistabs.entrypoints

import ghidra.app.CorePluginPackage
import ghidra.app.plugin.PluginCategoryNames
import ghidra.app.plugin.ProgramPlugin
import ghidra.app.services.GoToService
import ghidra.framework.plugintool.PluginInfo
import ghidra.framework.plugintool.PluginTool
import ghidra.framework.plugintool.util.PluginStatus
import ghidra.program.model.listing.Program
import ghistabs.hierarchy.ClassHierarchyProvider

/**
 * `Window > Class Hierarchy`: a read-only tree of the program's C++ classes and their bases, after the
 * one astrelsky's Ghidra-Cpp-Class-Analyzer docks, over the stabs' own class graph and the classes the
 * vtable sweep found.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Show the C++ class hierarchy the stabs describe.",
    description = "Adds a 'Class Hierarchy' window: each class under its namespace, expanding into its " +
        "direct bases (from the stabs, or from the typeinfo of a class only the vtable sweep found).",
    servicesRequired = [GoToService::class],
    servicesProvided = [],
    eventsConsumed = [],
)
class ClassHierarchyPlugin(tool: PluginTool) : ProgramPlugin(tool) {
    private val provider = ClassHierarchyProvider(this)

    override fun programActivated(program: Program) = provider.setProgram(program)

    override fun programDeactivated(program: Program) = provider.setProgram(null)

    override fun dispose() {
        provider.dispose()
        super.dispose()
    }
}
