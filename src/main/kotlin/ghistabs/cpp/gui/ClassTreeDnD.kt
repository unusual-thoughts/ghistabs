package ghistabs.cpp.gui

import docking.DialogComponentProvider
import docking.widgets.OptionDialog
import docking.widgets.textfield.IntegerTextField
import docking.widgets.tree.GTreeNode
import docking.widgets.tree.support.GTreeDragNDropHandler
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghistabs.cpp.Access
import ghistabs.cpp.gui.ClassHierarchy.*
import ghistabs.namespaceAt
import ghistabs.runTransaction
import ghistabs.startsWith
import java.awt.GridLayout
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.Transferable
import java.awt.dnd.DnDConstants
import java.math.BigInteger
import javax.swing.*

/**
 * Drag and drop in the Class Hierarchy window. A class dropped on another becomes its child there:
 * normally one of its bases, with Show Derived Classes on a class derived from it. Moving takes the
 * class from under the node it was dragged from; copying (Ctrl) leaves it there too, and dropping it
 * on the root or a namespace only takes it away. No drop may make a class its own base.
 *
 * A namespace dropped on another or on the root moves there, and so does a class dragged from where
 * it is filed under its namespace, with the data type categories and structs filed by their path
 * ([relocateNamespace]).
 *
 * Members dropped on a class move into its namespace.
 *
 * Before changing what the stabs, RTTI or a mangled name state, it asks; before adding a base, how the
 * class holds it (virtual, access, offset), placing it in the class's struct when given an offset.
 */
internal class ClassTreeDnD(
    private val tool: PluginTool,
    private val parent: () -> JComponent,
    private val program: () -> Program?,
    private val hierarchy: () -> ClassHierarchy?,
    private val inverted: () -> Boolean,
    private val status: (String) -> Unit,
) : GTreeDragNDropHandler {
    private val flavor = DataFlavor(DataFlavor.javaJVMLocalObjectMimeType + ";class=java.util.List", "class tree nodes")
    private var dragged: List<GTreeNode> = emptyList()

    override fun getSupportedDataFlavors(transferNodes: List<GTreeNode>) = arrayOf(flavor)

    override fun getTransferData(transferNodes: List<GTreeNode>, flavor: DataFlavor): Any = transferNodes

    override fun getSupportedDragActions() = DnDConstants.ACTION_COPY_OR_MOVE

    override fun isStartDragOk(dragUserData: List<GTreeNode>, dragAction: Int): Boolean {
        val classOk = dragUserData.singleOrNull().let { (it is ClassNode && it.info != null) || it is NamespaceNode }
        val membersOk = dragUserData.isNotEmpty() &&
            dragUserData.all { it is MemberNode && it.member.symbolId != null && it.member.library == null }
        dragged = dragUserData.takeIf { classOk || membersOk }.orEmpty()
        return dragged.isNotEmpty()
    }

    override fun isDropSiteOk(destUserData: GTreeNode?, flavors: Array<DataFlavor>, dropAction: Int): Boolean {
        val h = hierarchy() ?: return false
        val dest = destUserData ?: return false
        val members = dragged.filterIsInstance<MemberNode>()
        if (members.isNotEmpty()) {
            val target = (dest as? ClassNode)?.info?.let { h[it.id] }
            return target != null && target.origin != Origin.IMPORTED &&
                members.any { it.member !in target.members }
        }
        var why: String? = null
        val ok = when (val path = movedPath(dest)) {
            null -> plan(h, dragged.singleOrNull() as? ClassNode ?: return false, dest, dropAction) { why = it }
                .isNotEmpty()

            else -> namespaceMoveRefusal(path, pathOf(dest)!!).also { why = it } == null
        }
        status(why?.let { "Can't drop: $it" } ?: " ")
        return ok
    }

    override fun drop(destUserData: GTreeNode, transferable: Transferable, dropAction: Int) {
        status(" ")
        val h = hierarchy() ?: return
        val p = program() ?: return
        val members = dragged.filterIsInstance<MemberNode>()
        val target = (destUserData as? ClassNode)?.info?.let { h[it.id] }
        if (members.isNotEmpty() && target != null) {
            moveMembers(p, members.map { it.member }, target)
            return
        }
        movedPath(destUserData)?.let { from ->
            moveNamespace(p, h, from, pathOf(destUserData)!!)
            return
        }
        val node = dragged.singleOrNull() as? ClassNode ?: return
        applyEdits(p, plan(h, node, destUserData, dropAction))
    }

    // A namespace node's path, or the root's (empty); null for a class.
    private fun pathOf(node: GTreeNode): List<String>? = when (node) {
        is ClassHierarchyRootNode -> emptyList()
        is NamespaceNode -> node.path
        else -> null
    }

    // The namespace path a drop on [dest] moves: a namespace's anywhere it is dropped, a class's filed
    // under its namespace dropped on another namespace or the root. Null when the drop edits bases.
    private fun movedPath(dest: GTreeNode): List<String>? {
        if (pathOf(dest) == null) return null
        return when (val node = dragged.singleOrNull()) {
            is NamespaceNode -> node.path
            is ClassNode -> node.info?.path?.takeIf { node.edge == null }
            else -> null
        }
    }

    private fun moveNamespace(p: Program, h: ClassHierarchy, from: List<String>, to: List<String>) {
        val ns = p.namespaceAt(from) ?: return
        val parent = p.namespaceAt(to) ?: return
        val named = h.classes.filter { it.path.startsWith(from) }
            .mapNotNull { c -> c.solidSource()?.let { "  ${c.qualifiedName}: $it" } }
        val what = from.joinToString("::")
        if (named.isNotEmpty() &&
            !confirm("Move $what", "These classes' names come from:\n${named.joinToString("\n")}\nMove anyway?")
        ) {
            return
        }
        val skipped = runCatching { p.runTransaction("Move $what") { p.relocateNamespace(ns, parent) } }
            .onFailure { Msg.showError(this, parent(), "Move $what", it.message, it) }.getOrNull()
        if (!skipped.isNullOrEmpty()) {
            Msg.showWarn(this, parent(), "Move $what", "Kept their old place:\n" + skipped.joinToString("\n"))
        }
    }

    private fun plan(
        h: ClassHierarchy,
        node: ClassNode,
        dest: GTreeNode,
        action: Int,
        why: (String) -> Unit = {},
    ): List<BaseEdit> = h.planDrop(
        dragged = node.info?.let { h[it.id] } ?: return emptyList(),
        edge = node.edge,
        parent = (node.parent as? ClassNode)?.info?.let { h[it.id] },
        // Only a class takes a base; the root and a namespace take one away.
        dest = when (dest) {
            is ClassNode -> dest.info?.let { h[it.id] } ?: return emptyList()
            is ClassHierarchyRootNode, is NamespaceNode -> null
            else -> return emptyList()
        },
        inverted = inverted(),
        move = action and DnDConstants.ACTION_MOVE != 0,
        reason = why,
    )

    private fun confirm(title: String, message: String) =
        OptionDialog.showYesNoDialog(parent(), title, message) == OptionDialog.YES_OPTION

    private fun applyEdits(p: Program, edits: List<BaseEdit>) {
        for (edit in edits) {
            val source = edit.owner.solidSource() ?: continue
            val change = if (edit.added == null) "remove ${edit.removed?.name}" else "add ${edit.added.qualifiedName}"
            val ok = confirm(
                "Change ${edit.owner.qualifiedName}'s bases",
                "${edit.owner.qualifiedName}'s bases come from $source. ${change.replaceFirstChar(Char::uppercase)} " +
                    "as a base anyway?",
            )
            if (!ok) return
        }
        val addition = edits.firstOrNull { it.added != null }
        val clause = addition?.let { askClause(p, it) ?: return }
        val place = addition?.added?.let { base ->
            clause?.offset?.toInt()?.let { offset -> base to offset }
        }
        if (place != null) {
            val hit = p.overwrittenBy(addition.owner, place.first, place.second)
            val list = hit.joinToString("\n") { "  +0x%x %s".format(it.offset, it.fieldName ?: it.defaultFieldName) }
            if (hit.isNotEmpty() &&
                !confirm("Place ${place.first.qualifiedName}", "Placing it overwrites:\n$list\nGo on?")
            ) {
                return
            }
        }
        val skipped = runCatching {
            p.runTransaction("Edit class hierarchy") {
                for (edit in edits) p.setBases(edit.owner, edit.bases(clause.takeIf { edit.added != null }))
                place?.let { (base, offset) ->
                    val count = addition.bases(clause).size
                    p.placeBase(addition.owner, base, offset, clause!!.isVirtual, count)
                }
            }
        }.onFailure { Msg.showError(this, parent(), "Edit Class Hierarchy", it.message, it) }.getOrNull()
        skipped?.let { Msg.showWarn(this, parent(), "Edit Class Hierarchy", "The base wasn't placed: $it") }
    }

    /** Asks how [edit]'s owner holds the base it gains; the clause it replaces, if any, gives the defaults. */
    private fun askClause(p: Program, edit: BaseEdit): BaseRef? {
        val base = edit.added ?: return null
        val old = edit.removed
        val struct = p.structOf(edit.owner)
        val part = p.embeddingOf(base)
        // Where the struct already holds it, else first for a first non-virtual base.
        val found = struct?.definedComponents?.firstOrNull { part != null && it.dataType.isEquivalent(part) }?.offset
        val offset = old?.offset ?: found?.toLong() ?: 0L.takeIf { edit.owner.bases.isEmpty() }
        val dialog = BaseDialog(
            edit.owner,
            base,
            old?.isVirtual ?: false,
            old?.access ?: Access.PUBLIC,
            offset,
            struct != null,
        )
        tool.showDialog(dialog, parent())
        return dialog.result
    }

    private fun moveMembers(p: Program, members: List<Member>, target: ClassInfo) {
        val moving = members.filter { it !in target.members }
        val tied = moving.mapNotNull { m -> p.memberSource(m)?.let { "  ${m.label}: $it" } }
        if (tied.isNotEmpty() && !confirm(
                "Move to ${target.qualifiedName}",
                "These say which class they belong to:\n${tied.joinToString("\n")}\nMove them anyway?",
            )
        ) {
            return
        }
        val failed = p.runTransaction("Move members to ${target.qualifiedName}") {
            moving.mapNotNull { m ->
                runCatching { p.moveMember(m, target) }.exceptionOrNull()?.let { "${m.label}: ${it.message}" }
            }
        }
        if (failed.isNotEmpty()) {
            Msg.showWarn(
                this,
                parent(),
                "Move Members",
                "Not moved:\n" + failed.joinToString("\n"),
            )
        }
    }

    /** Virtual or not, access, and the offset to place the base at (blank: don't place it). */
    private class BaseDialog(
        owner: ClassInfo,
        private val base: ClassInfo,
        isVirtual: Boolean,
        access: Access,
        offset: Long?,
        private val canPlace: Boolean,
    ) : DialogComponentProvider("Add ${base.qualifiedName} as a base of ${owner.qualifiedName}") {
        private val virtual = JCheckBox("Virtual", isVirtual)
        private val accessBox = JComboBox(Access.entries.toTypedArray()).apply { selectedItem = access }

        // Ghidra's own number field, hex to start with, a 0x prefix or its lack switching it; blank allowed.
        // setHexMode, deprecated in 12.2 for setFormat, is the one every Ghidra this builds for has.
        @Suppress("DEPRECATION")
        private val offsetField = IntegerTextField(10).apply {
            setAllowNegativeValues(false)
            maxValue = BigInteger.valueOf(Int.MAX_VALUE.toLong())
            setHexMode()
            setShowNumberMode(true)
            offset?.let(::setValue)
            setEnabled(canPlace)
        }
        var result: BaseRef? = null
            private set

        init {
            addWorkPanel(
                JPanel(GridLayout(0, 2, 8, 4)).apply {
                    add(JLabel("Inheritance:"))
                    add(virtual)
                    add(JLabel("Access:"))
                    add(accessBox)
                    add(JLabel("Offset in the struct (blank: don't place it):"))
                    add(offsetField.component)
                },
            )
            addOKButton()
            addCancelButton()
        }

        override fun okCallback() {
            result = BaseRef(
                base.qualifiedName,
                base.id,
                virtual.isSelected,
                accessBox.selectedItem as Access,
                offsetField.value?.toLong()?.takeIf { canPlace },
            )
            close()
        }
    }
}
