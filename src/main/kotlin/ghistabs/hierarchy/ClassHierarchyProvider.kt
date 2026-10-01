package ghistabs.hierarchy

import docking.ActionContext
import docking.action.DockingAction
import docking.action.ToolBarData
import docking.widgets.tree.GTree
import docking.widgets.tree.GTreeNode
import ghidra.app.services.DataTypeManagerService
import ghidra.app.services.GoToService
import ghidra.framework.model.DomainObjectChangedEvent
import ghidra.framework.model.DomainObjectListener
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.Plugin
import ghidra.program.model.listing.Program
import ghidra.util.HelpLocation
import ghidra.util.Msg
import ghidra.util.task.SwingUpdateManager
import ghistabs.importer.ClassHierarchyRecord
import ghistabs.importer.ImportOptions.Companion.isStabsDone
import resources.Icons
import java.awt.BorderLayout
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.SwingUtilities

/**
 * The docked Class Hierarchy window: [ClassHierarchyRootNode] over the current program, rebuilt off the
 * Swing thread when the program changes while the window shows. Double-click (or Enter) goes to a
 * class's vtable, else its typeinfo, else selects its struct in the Data Type Manager.
 */
class ClassHierarchyProvider(private val plugin: Plugin) :
    ComponentProviderAdapter(plugin.tool, NAME, plugin.name),
    DomainObjectListener {
    companion object {
        const val NAME = "Class Hierarchy"
    }

    private val tree = GTree(placeholder("No program")).apply { isRootVisible = true }
    private val status = JLabel(" ")
    private val panel = JPanel(BorderLayout()).apply {
        add(tree, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    private var program: Program? = null
    private val builder = Executors.newSingleThreadExecutor {
        Thread(it, "Stabs class hierarchy").apply {
            isDaemon =
                true
        }
    }
    private val generation = AtomicInteger()

    // Analysis fires change events by the thousand: wait for a lull.
    private val updater = SwingUpdateManager(1_000, 10_000) { rebuild() }

    init {
        icon = CLASS_ICON
        helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
        addToToolbar()
        tool.addComponentProvider(this, false)
        tree.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (!e.isConsumed && SwingUtilities.isLeftMouseButton(e) && e.clickCount == 2) {
                    e.consume()
                    goToSelected()
                }
            }
        })
        tree.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER) goToSelected()
            }
        })
        addLocalAction(
            object : DockingAction("Refresh Class Hierarchy", plugin.name) {
                override fun actionPerformed(context: ActionContext?) = rebuild()
            }.apply {
                toolBarData = ToolBarData(Icons.REFRESH_ICON, null)
                description = "Rebuild the class hierarchy from the program"
                helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
            },
        )
    }

    override fun getComponent(): JComponent = panel

    fun setProgram(newProgram: Program?) {
        if (newProgram === program) return
        program?.removeListener(this)
        program = newProgram
        newProgram?.addListener(this)
        rebuild()
    }

    override fun componentShown() = rebuild()

    override fun domainObjectChanged(ev: DomainObjectChangedEvent) {
        if (isVisible) updater.update()
    }

    private fun rebuild() {
        val p = program
        val gen = generation.incrementAndGet()
        if (p == null || !isVisible) {
            if (p == null) tree.setRootNode(placeholder("No program"))
            return
        }
        status.text = "Reading classes…"
        builder.execute {
            val result = runCatching { ClassHierarchy.of(p) }
            SwingUtilities.invokeLater {
                if (gen != generation.get() || p !== program) return@invokeLater
                result.onSuccess { show(p, it) }.onFailure {
                    Msg.error(this, "Class hierarchy failed: ${it.message}", it)
                    status.text = "Failed: ${it.message}"
                }
            }
        }
    }

    private fun show(p: Program, hierarchy: ClassHierarchy) {
        tree.setRootNode(ClassHierarchyRootNode(p.name, hierarchy))
        val counts = hierarchy.classes.groupingBy { it.origin }.eachCount()
        val stabs = counts[ClassHierarchy.Origin.STABS] ?: 0
        val swept = hierarchy.classes.size - stabs
        status.text = buildString {
            append("$stabs from stabs, $swept swept")
            // Imported before the record existed: the stabs classes read as swept until a re-import.
            if (p.isStabsDone && ClassHierarchyRecord.read(p) == null) {
                append(" (no stabs record: Tools > Stabs > Re-import to add it)")
            }
        }
    }

    private fun goToSelected() {
        val node = tree.selectionPath?.lastPathComponent as? ClassNode ?: return
        val info = node.info ?: return
        val address = info.address
        when {
            address != null -> tool.getService(GoToService::class.java)?.goTo(address)
            info.struct != null -> tool.getService(DataTypeManagerService::class.java)?.setDataTypeSelected(info.struct)
        }
    }

    fun dispose() {
        program?.removeListener(this)
        program = null
        updater.dispose()
        builder.shutdownNow()
        tree.dispose()
    }

    private fun placeholder(text: String): GTreeNode = object : GTreeNode() {
        override fun getName() = text
        override fun getIcon(expanded: Boolean) = null
        override fun getToolTip(): String? = null
        override fun isLeaf() = true
    }
}
