package ghicpp.gui

import docking.widgets.tree.GTreeNode
import docking.widgets.tree.support.GTreeDragNDropHandler
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.ClassHierarchy.Origin
import ghicpp.hierarchy.Drop
import ghicpp.hierarchy.checkNamespaceMove
import ghicpp.hierarchy.planDrop
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.Transferable
import java.awt.dnd.DnDConstants

/**
 * Drag and drop in the Class Hierarchy window, as the Symbol Tree's `SymbolGTreeDragNDropHandler` is in
 * its own: a class onto another class edits bases, a class or a namespace onto a namespace or the root
 * moves it ([movedPath]), members onto a class move them into it.
 */
internal class ClassDnDHandler(private val window: ClassTree) : GTreeDragNDropHandler {
    private val flavor = DataFlavor(
        DataFlavor.javaJVMLocalObjectMimeType + ";class=java.util.List",
        "class tree nodes",
    )
    private var dragged: List<GTreeNode> = emptyList()

    override fun getSupportedDataFlavors(nodes: List<GTreeNode>) = arrayOf(flavor)
    override fun getTransferData(nodes: List<GTreeNode>, flavor: DataFlavor): Any = nodes
    override fun getSupportedDragActions() = DnDConstants.ACTION_COPY_OR_MOVE

    override fun isStartDragOk(nodes: List<GTreeNode>, action: Int): Boolean {
        val classOk = nodes.singleOrNull().let {
            (it is ClassNode && it.info != null) || it is NamespaceNode
        }
        // A vtable's or typeinfo's label names its class: moving it would only make it lie.
        val membersOk = nodes.isNotEmpty() &&
            nodes.all { it is MemberNode && it.member.isMovable }
        dragged = nodes.takeIf { classOk || membersOk }.orEmpty()
        return dragged.isNotEmpty()
    }

    override fun isDropSiteOk(dest: GTreeNode, flavors: Array<DataFlavor>, action: Int): Boolean {
        val h = window.shown ?: return false
        val members = dragged.filterIsInstance<MemberNode>()
        if (members.isNotEmpty()) {
            val target = (dest as? ClassNode)?.info?.let { h[it.id] }
            return target != null && target.origin != Origin.LIBRARY &&
                members.any { it.member !in target.members }
        }
        val err = h.dropRefusal(dragged.singleOrNull() ?: return false, dest, action)
        window.dropNote(err)
        return err == null
    }

    override fun drop(dest: GTreeNode, transferable: Transferable, action: Int) {
        window.dropNote(null)
        val h = window.shown ?: return
        val p = window.program ?: return
        val members = dragged.filterIsInstance<MemberNode>()
        val target = (dest as? ClassNode)?.takeIf { members.isNotEmpty() }?.info?.let { h[it.id] }
        val ns = movedPath(dragged.singleOrNull(), dest)
        val node = dragged.singleOrNull() as? ClassNode
        val before = p.modificationNumber
        when {
            target != null -> p.moveMembers(members.map { it.member }, target, window.tool, window.component)
            ns != null -> p.moveNamespace(h, ns, dest.namespacePath!!, window.component)
            node != null -> p.applyEdits(h.planDrop(node, dest, action).edits, window.tool, window.component)
        }
        // Once the rebuild shows it, open the node dropped on, to show what landed there.
        if (p.modificationNumber != before) window.revealAfterRebuild(dest, dragged.map { it.name })
    }
}

/**
 * The namespace path dropping [dragged] on [dest] moves: a namespace's anywhere it is dropped, a class's
 * filed under its namespace dropped on another namespace or the root. Null when the drop edits bases.
 */
internal fun movedPath(dragged: GTreeNode?, dest: GTreeNode): List<String>? {
    if (dest.namespacePath == null) return null
    return when (dragged) {
        is NamespaceNode -> dragged.path
        is ClassNode -> dragged.info?.path?.takeIf { dragged.edge == null }
        else -> null
    }
}

/** Why [dragged], a class's or a namespace's node, can't be dropped on [dest]; null when it can. */
fun ClassHierarchy.dropRefusal(dragged: GTreeNode, dest: GTreeNode, action: Int) =
    when (val from = movedPath(dragged, dest)) {
        null -> when (dragged) {
            is ClassNode -> planDrop(dragged, dest, action).error
            else -> "a namespace only drops on another namespace or the root"
        }

        else -> checkNamespaceMove(from, dest.namespacePath!!)
    }

/** What dropping [node] on [dest] does to the bases, the way round [node]'s tree runs. */
internal fun ClassHierarchy.planDrop(node: ClassNode, dest: GTreeNode, action: Int): Drop {
    // The tree's own way round: normally a node's children are its bases, inverted its derived classes.
    val inverted = (node.root as? ClassTreeRoot)?.inverted == true
    val dragged = node.info?.let { this[it.id] ?: return Drop.Illegal(STALE) }
        ?: return Drop.Illegal("the program has no class ${node.name}")
    val move = action and DnDConstants.ACTION_MOVE != 0
    val parent = (node.parent as? ClassNode)?.info?.let { this[it.id] }
    // Only a class takes a base; the root and a namespace take one away.
    val target = when (dest) {
        is ClassNode -> dest.info?.let { this[it.id] ?: return Drop.Illegal(STALE) }
            ?: return Drop.Illegal("the program has no class ${dest.name}")

        is ClassTreeRoot, is NamespaceNode -> null

        else -> return Drop.Illegal("a class only drops on another class, a namespace or the root")
    }
    return planDrop(
        owner = target?.takeUnless { inverted } ?: dragged,
        base = target?.let { if (inverted) it else dragged },
        // Normally the clause is the parent's, naming the dragged class; inverted, the dragged class's own.
        removedFrom = (if (inverted) dragged else parent)?.takeIf { node.edge != null && move },
        edge = node.edge,
    )
}

// The tree shows classes the program has changed since: the rebuild is on its way.
private const val STALE = "the tree is out of date, wait for it to refresh"
