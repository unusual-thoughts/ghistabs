package ghistabs.hierarchy

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.action.ToggleDockingAction
import docking.action.ToolBarData
import docking.widgets.tree.GTree
import docking.widgets.tree.GTreeNode
import generic.theme.GIcon
import ghidra.app.services.DataTypeManagerService
import ghidra.app.services.GoToService
import ghidra.framework.model.DomainObjectChangedEvent
import ghidra.framework.model.DomainObjectListener
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.Plugin
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.util.HTMLUtilities
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
 * Swing thread when the program changes while the window shows. Double-click (or Enter) on a member
 * goes to it; on a class, opens its struct in the structure editor, else goes to its vtable or typeinfo.
 */
class ClassTree(private val plugin: Plugin) :
    ComponentProviderAdapter(plugin.tool, NAME, plugin.name),
    DomainObjectListener {
    companion object {
        const val NAME = "Class Hierarchy"
        private val STRUCT_ICON = GIcon("icon.plugin.datatypes.structure")
        private val VTABLE_ICON = GIcon("icon.plugin.navigation.bytes")
    }

    private val tree = GTree(placeholder("No program")).apply {
        isRootVisible = true
        setCellRenderer(ClassTreeRenderer())
    }
    private val status = JLabel(" ")
    private val panel = JPanel(BorderLayout()).apply {
        add(tree, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    private var program: Program? = null
    private var shown: ClassHierarchy? = null
    private var showMembers = true
    private var inverted = false
    private var expandAll = false
    private var showEmpty = false
    private var navigateIncoming: ToggleDockingAction
    private var lastLocation: ProgramLocation? = null
    private val builder = Executors.newSingleThreadExecutor {
        Thread(it, "Stabs class hierarchy").apply {
            isDaemon = true
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
                    openSelected()
                }
            }
        })
        tree.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER) openSelected()
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
        addLocalAction(
            object : ToggleDockingAction("Show Class Members", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    showMembers = isSelected
                    reshow()
                }
            }.apply {
                toolBarData = ToolBarData(GIcon("icon.plugin.symboltree.node.function"), null)
                description = "Show each class's functions and labels, or only the classes"
                isSelected = true
                helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
            },
        )
        addLocalAction(
            object : ToggleDockingAction("Show Empty Classes", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    showEmpty = isSelected
                    reshow()
                }
            }.apply {
                toolBarData = ToolBarData(CLASS_ICON, null)
                description = "Also show the classes with nothing in them: no member, vtable, typeinfo, base " +
                    "or derived class (C structs and STL tags, mostly)"
                helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
            },
        )
        addLocalAction(
            object : ToggleDockingAction("Expand All Classes", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    expandAll = isSelected
                    if (expandAll) {
                        tree.expandAll()
                    } else {
                        tree.collapseAll(tree.viewRoot)
                        tree.expandPath(tree.viewRoot)
                    }
                }
            }.apply {
                toolBarData = ToolBarData(GIcon("icon.expand.all"), null)
                description = "Keep every class expanded, through rebuilds too"
                helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
            },
        )
        addLocalAction(
            object : ToggleDockingAction("Show Derived Classes", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    inverted = isSelected
                    showDirection()
                    reshow()
                }

                // The arrow and the tooltip say which way the tree runs now: up to the bases, or down
                // to the derived classes.
                fun showDirection() {
                    toolBarData = ToolBarData(GIcon(if (isSelected) "icon.down" else "icon.up"), null)
                    description = if (isSelected) {
                        "Basal classes at the root, each expanding into the classes derived from it. " +
                            "Toggle off to expand each class into its bases"
                    } else {
                        "Each class expands into its bases. " +
                            "Toggle on to put the basal classes at the root, expanding into the classes derived from them"
                    }
                }
            }.apply {
                showDirection()
                helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
            },
        )
        addLocalAction(
            object : ToggleDockingAction("Navigate on Incoming", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    if (isSelected) lastLocation?.let(::select)
                }
            }.apply {
                toolBarData = ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, null)
                description = HTMLUtilities.toHTML(
                    "Toggle <b>On</b> means to select the matching tree\nsymbol on program location changes",
                )
                helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
            }.also { navigateIncoming = it },
        )
        addLocalAction(
            object : DockingAction("Edit class struct", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    selectedClass?.structId?.let { openStruct(it) }
                }
            }.apply {
                popupMenuData = MenuData(arrayOf("Edit class struct"), STRUCT_ICON)
                popupWhen { selectedClass?.structId != null }
            },
        )
        addLocalAction(
            object : DockingAction("Edit vtable struct", plugin.name) {
                override fun actionPerformed(context: ActionContext?) {
                    selectedClass?.vftableStructId?.let { openStruct(it) }
                }
            }.apply {
                popupMenuData = MenuData(arrayOf("Edit vtable struct"), VTABLE_ICON)
                popupWhen { selectedClass?.vftableStructId != null }
            },
        )
    }

    override fun getComponent(): JComponent = panel

    fun setProgram(newProgram: Program?) {
        if (newProgram === program) return
        program?.removeListener(this)
        program = newProgram
        shown = null
        newProgram?.addListener(this)
        rebuild()
    }

    override fun componentShown() = rebuild()

    override fun domainObjectChanged(ev: DomainObjectChangedEvent) {
        if (isVisible) updater.update()
    }

    private fun rebuild() {
        val gen = generation.incrementAndGet()
        program?.takeIf { isVisible }?.let { p ->
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
        } ?: run { tree.setRootNode(placeholder("No program")) }
    }

    private fun show(p: Program, hierarchy: ClassHierarchy) {
        shown = hierarchy
        reshow()
        val counts = hierarchy.classes.groupingBy { it.origin }.eachCount()
        val stabs = counts[ClassHierarchy.Origin.STABS] ?: 0
        val swept = hierarchy.classes.size - stabs
        status.text = buildString {
            append("$stabs from stabs, $swept swept")
            val empty = hierarchy.classes.count(hierarchy::isEmpty)
            if (empty > 0) append(", $empty empty")
            // Imported before the record existed: the stabs classes read as swept until a re-import.
            if (p.isStabsDone && !ClassHierarchyRecord.isRecorded(p)) {
                append(" (no stabs record: Tools > Stabs > Re-import to add it)")
            }
        }
    }

    /** The shown hierarchy again, as the toolbar toggles now want it. */
    private fun reshow() {
        val p = program ?: return
        val h = shown ?: return
        tree.replaceRoot(ClassHierarchyRootNode(p.name, h, showMembers, inverted, showEmpty))
        if (expandAll) tree.expandAll()
    }

    /** The tool's location moved: with Navigate on Incoming on, select what the tree shows for it. */
    fun locationChanged(loc: ProgramLocation?) {
        lastLocation = loc
        if (loc != null && navigateIncoming.isSelected && isVisible) select(loc)
    }

    /** Select what [loc] is in the tree: see [ClassHierarchyRootNode.nodeAt]. */
    private fun select(loc: ProgramLocation) {
        val p = program?.takeIf { it === loc.program } ?: return
        val addr = loc.address ?: return
        val root = tree.modelRoot as? ClassHierarchyRootNode ?: return
        val at = listOfNotNull(addr, p.functionManager.getFunctionContaining(addr)?.entryPoint).map(Address::toString)
        root.nodeAt(at.distinct())?.let(tree::setSelectedNode)
    }

    private fun Program.goTo(at: String?) = at?.let(addressFactory::getAddress)
        ?.let { tool.getService(GoToService::class.java)?.goTo(it) }

    private fun openSelected() = program?.apply {
        when (val selected = tree.selectionPath?.lastPathComponent) {
            is MemberNode -> goTo(selected.member.address)
            is ClassNode -> selected.info?.let { info -> goTo(info.address) }
        }
    }

    private val selectedClass get() = (tree.selectionPath?.lastPathComponent as? ClassNode)?.info

    private fun openStruct(id: Long) = program?.apply {
        dataTypeManager.getDataType(id)?.let {
            tool.getService(DataTypeManagerService::class.java)?.edit(it)
        }
    }

    fun dispose() {
        program?.removeListener(this)
        program = null
        shown = null
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

/**
 * Swap in a rebuilt tree, keeping what was expanded and selected: the new nodes are new objects, so
 * each path is carried over by its [steps].
 */
internal fun GTree.replaceRoot(root: GTreeNode) {
    val expanded = expandedPaths.map { steps(it.lastPathComponent as GTreeNode) }
    val selected = selectionPaths.orEmpty().map { steps(it.lastPathComponent as GTreeNode) }
    setRootNode(root)
    expanded.sortedBy { it.size }.forEach { path -> root.find(path)?.let(::expandPath) }
    selected.mapNotNull(root::find).takeIf { it.isNotEmpty() }?.let(::setSelectedNodes)
}

/**
 * [node]'s path below the root by name, with each node's rank among same-named siblings (overloads, a
 * direct and an indirect `Base`) to tell those apart.
 */
internal fun steps(node: GTreeNode): List<Pair<String, Int>> =
    generateSequence(node) { it.parent }.takeWhile { it.parent != null }.toList().asReversed().map { n ->
        n.name to n.parent.children.filter { it.name == n.name }.indexOf(n)
    }

/** The node at [steps] below this root, in a tree rebuilt since they were taken. */
internal fun GTreeNode.find(steps: List<Pair<String, Int>>): GTreeNode? =
    steps.fold(this as GTreeNode?) { node, (name, rank) -> node?.children?.filter { it.name == name }?.getOrNull(rank) }
