package ghicpp.gui

import docking.ActionContext
import docking.action.ToggleDockingAction
import docking.widgets.tree.GTree
import docking.widgets.tree.GTreeNode
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin
import ghicpp.ClassHierarchyRecords.Companion.areClassesRecorded
import ghicpp.ClassNaming
import ghicpp.ClassRecordSource
import ghicpp.abi.msvc.Msvc
import ghicpp.analyzers.ItaniumClassAnalyzer
import ghicpp.analyzers.MsvcClassAnalyzer
import ghicpp.hierarchy.BaseEdit
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.*
import ghicpp.hierarchy.reclause
import ghidra.app.context.ProgramSymbolActionContext
import ghidra.app.services.GoToService
import ghidra.framework.model.DomainObjectChangedEvent
import ghidra.framework.model.DomainObjectListener
import ghidra.framework.plugintool.ComponentProviderAdapter
import ghidra.framework.plugintool.Plugin
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.util.ProgramLocation
import ghidra.util.HelpLocation
import ghidra.util.Msg
import ghidra.util.task.SwingUpdateManager
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
 * The docked Class Hierarchy window: [ClassTreeRoot] over the current program, rebuilt off the
 * Swing thread when the program changes while the window shows. Double-click (or Enter) on a member
 * goes to it; on a class, to its vtable or typeinfo. With Navigate on Outgoing on, selecting does too.
 *
 * Its action context is the selected nodes' symbols (a member's, a class's namespace's), so the tool's
 * symbol actions (Edit Function, …) work on them, and the Symbol Tree's own that suit a member are
 * here: Rename, Delete, Show References to, Set Primary, Pin.
 *
 * A [ClassRecordSource] tells another source's class record (the stabs import's) from the class pass's.
 *
 * Its toolbar ([addToolbarActions]) and popup actions ([addSelectionActions]) are in ClassActions.kt,
 * drag and drop in [ClassDnDHandler]. Below it here: going to and selecting nodes ([select], [openSelected]),
 * carrying paths over a rebuild ([replaceRoot]) and the status line ([statusLine]).
 */
class ClassTree(plugin: Plugin) :
    ComponentProviderAdapter(plugin.tool, NAME, plugin.name),
    DomainObjectListener {
    companion object {
        const val NAME = "Class Hierarchy"
    }

    internal val tree = GTree(placeholder("No program")).apply {
        isRootVisible = true
        cellRenderer = ClassTreeRenderer()
        dragNDropHandler = ClassDnDHandler(this@ClassTree)
        addGTreeSelectionListener { e ->
            // Not when Navigate on Incoming selected it: that's where the listing already is.
            if (e.eventOrigin == EventOrigin.USER_GENERATED && navigateOutgoing.isSelected) openSelected()
            contextChanged()
        }
        addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.isConsumed || !SwingUtilities.isLeftMouseButton(e)) return
                if (e.clickCount == 2) {
                    e.consume()
                    openSelected()
                } else if (navigateOutgoing.isSelected && getNodeForLocation(e.x, e.y) === selectedNode) {
                    // A click on the node already selected changes no selection, and goes there all the same.
                    openSelected()
                }
            }
        })
        addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER) openSelected()
            }
        })
    }
    private val status = JLabel(" ")
    private val panel = JPanel(BorderLayout()).apply {
        add(tree, BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    internal var program: Program? = null
        private set

    // The status line's class counts, shown again once a drag's "can't drop" note is done with.
    private var counts = " "
    internal var shown: ClassHierarchy? = null
        private set
    internal var memberKinds: Set<MemberKind> = MemberKind.entries.toSet()
    internal var inverted = false
    internal var expandAll = false
    internal var showEmpty = false
    internal lateinit var navigateIncoming: ToggleDockingAction
    internal lateinit var navigateOutgoing: ToggleDockingAction
    internal var lastLocation: ProgramLocation? = null

    /** The node a drop landed on, by its [steps], and the names of what was dropped, to show on the next rebuild. */
    private data class Reveal(val dest: List<Pair<String, Int>>, val names: List<String>)
    private var reveal: Reveal? = null
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

        addToolbarActions()
        addSelectionActions()
    }

    override fun getActionContext(event: MouseEvent?): ActionContext {
        val p = program ?: return super.getActionContext(event)
        val symbols = tree.selectionPaths.orEmpty().mapNotNull { path ->
            when (val node = path.lastPathComponent) {
                is MemberNode -> node.member.symbolId?.let(p.symbolTable::getSymbol)
                is ClassNode -> node.info?.id?.let(p.symbolTable::getSymbol)
                else -> null
            }
        }
        return ProgramSymbolActionContext(this, p, symbols.distinct(), tree)
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

    internal fun rebuild() {
        val gen = generation.incrementAndGet()
        program?.takeIf { isVisible }?.let { p ->
            status.text = "Reading classes…"
            builder.execute {
                val result = runCatching { ClassHierarchy.of(p, ClassRecordSource.describedElsewhere(p)) }
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
        counts = p.statusLine(hierarchy)
        status.text = counts
    }

    /** The shown hierarchy again, as the toolbar toggles now want it. */
    internal fun reshow() {
        val p = program ?: return
        val h = shown ?: return
        val root = ClassTreeRoot(p.name, h, memberKinds, inverted, showEmpty)
        tree.replaceRoot(root)
        if (expandAll) tree.expandAll()
        reveal?.let { (steps, names) ->
            reveal = null
            val dest = root.find(steps) ?: return
            tree.expandPath(dest)
            dest.children.filter { it.name in names }.takeIf { it.isNotEmpty() }?.let(tree::setSelectedNodes)
        }
    }

    /** The status line during a drag: why the drop is refused, else the class counts again. */
    internal fun dropNote(refusal: String?) {
        status.text = refusal?.let { "Can't drop: $it" } ?: counts
    }

    /** Once the rebuild after a drop shows it, open [dest], the node dropped on, and select [names] in it. */
    internal fun revealAfterRebuild(dest: GTreeNode, names: List<String>) {
        reveal = Reveal(steps(dest), names)
    }

    /** The tool's location moved: with Navigate on Incoming on, select what the tree shows for it. */
    fun locationChanged(loc: ProgramLocation?) {
        lastLocation = loc
        if (loc != null && navigateIncoming.isSelected && isVisible) select(loc)
    }

    internal val selectedNode: GTreeNode? get() = tree.selectionPath?.lastPathComponent as? GTreeNode

    internal val selectedClass get() = (tree.selectionPath?.lastPathComponent as? ClassNode)?.info

    internal val selectedMember get() = (tree.selectionPath?.lastPathComponent as? MemberNode)?.member

    /**
     * The selected class's base clause, as an edit of the class holding it that keeps the base: normally
     * the clause of the class above it, inverted its own, naming the class above.
     */
    internal val selectedClause: BaseEdit? get() {
        val h = shown ?: return null
        val node = tree.selectionPath?.lastPathComponent as? ClassNode ?: return null
        val edge = node.edge ?: return null
        val inverted = (node.root as? ClassTreeRoot)?.inverted == true
        val owner = (if (inverted) node else node.parent as? ClassNode)?.info?.let { h[it.id] } ?: return null
        return h.reclause(owner, edge)
    }

    /** The selected members, each with the class listing it. */
    internal val selectedMembers: List<Pair<Member, ClassView>> get() =
        tree.selectionPaths.orEmpty().mapNotNull { path ->
            val member = (path.lastPathComponent as? MemberNode)?.member ?: return@mapNotNull null
            (path.parentPath?.lastPathComponent as? ClassNode)?.info?.let { member to it }
        }

    /** The base function the selected member overrides, under the class listing it. */
    internal val selectedOverridden: Member? get() {
        val path = tree.selectionPath ?: return null
        val member = (path.lastPathComponent as? MemberNode)?.member ?: return null
        val cls = (path.parentPath?.lastPathComponent as? ClassNode)?.info ?: return null
        return shown?.overridden(cls, member)
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

/** Select what [loc] is in the tree: see [ClassTreeRoot.nodeAt]. */
internal fun ClassTree.select(loc: ProgramLocation) {
    val p = program?.takeIf { it === loc.program } ?: return
    val addr = loc.address ?: return
    val root = tree.modelRoot as? ClassTreeRoot ?: return
    val at = listOfNotNull(addr, p.functionManager.getFunctionContaining(addr)?.entryPoint).map(Address::toString)
    // Already there: a click on a class goes to its vtable, which mustn't then select the vtable.
    if (selectedNode?.address in at) return
    root.nodeAt(at.distinct())?.let(tree::setSelectedNode)
}

/** Go to [at], an address as the tree keeps it, in the program shown. */
internal fun ClassTree.goTo(at: String?) {
    val address = program?.addressFactory?.let { f -> at?.let(f::getAddress) } ?: return
    tool.getService(GoToService::class.java)?.goTo(address)
}

/** Go to the selected node: a member, or a class's vtable or typeinfo. */
internal fun ClassTree.openSelected() {
    selectedNode?.address?.let(::goTo)
}

/**
 * Swap in a rebuilt tree, keeping what was expanded and selected: the new nodes are new objects, so
 * each path is carried over by its [steps].
 */
private fun GTree.replaceRoot(root: GTreeNode) {
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
fun steps(node: GTreeNode): List<Pair<String, Int>> =
    generateSequence(node) { it.parent }.takeWhile { it.parent != null }.toList().asReversed().map { n ->
        n.name to n.parent.children.filter { it.name == n.name }.indexOf(n)
    }

/** The node at [steps] below this root, in a tree rebuilt since they were taken. */
fun GTreeNode.find(steps: List<Pair<String, Int>>): GTreeNode? =
    steps.fold(this as GTreeNode?) { node, (name, rank) -> node?.children?.filter { it.name == name }?.getOrNull(rank) }

/** The status line under the tree: [hierarchy]'s classes counted by where they came from, then [staleNote]. */
internal fun Program.statusLine(hierarchy: ClassHierarchy): String {
    val byOrigin = hierarchy.classes.groupingBy { it.origin }.eachCount()
    return buildString {
        // By source: the stabs, else what the class's typeinfo, its vtable or, failing both, its
        // namespace alone shows.
        append(
            Origin.entries.mapNotNull { origin -> byOrigin[origin]?.let { "$it ${origin.desc}" } }
                .ifEmpty { listOf("no classes") }.joinToString(", "),
        )
        val empty = hierarchy.classes.count(hierarchy::isEmpty)
        if (empty > 0) append(", $empty empty")
        staleNote()?.let { append(" ($it)") }
    }
}

/**
 * The status line's caveat when [this]'s classes may be under-attributed. Another source but no record (stabs
 * imported before the record existed): its classes count as from typeinfo or vtables until it records them.
 * RTTI but no record: analyzed before its class analyzer.
 */
private fun Program.staleNote(): String? = if (areClassesRecorded()) {
    null
} else {
    ClassRecordSource.hintFor(this) ?: when {
        symbolTable.getSymbols(Msvc.CLASS_HIERARCHY_DESCRIPTOR).hasNext() ->
            "no class record: Analysis > One Shot > ${MsvcClassAnalyzer.NAME} to add it"

        symbolTable.getSymbols(ClassNaming.TYPEINFO).hasNext() ->
            "no class record: Analysis > One Shot > ${ItaniumClassAnalyzer.NAME} to add it"

        else -> null
    }
}
