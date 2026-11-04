package ghistabs.cpp.gui

import docking.DialogComponentProvider
import docking.widgets.OptionDialog
import docking.widgets.textfield.IntegerTextField
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghistabs.cpp.Access
import ghistabs.cpp.gui.ClassHierarchy.*
import ghistabs.namespaceAt
import ghistabs.runTransaction
import ghistabs.startsWith
import java.awt.Component
import java.awt.GridLayout
import java.math.BigInteger
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel

/** Asks how [edit]'s owner holds the base it gains; the clause it replaces, if any, gives the defaults. */
private fun Program.askClause(edit: BaseEdit, tool: PluginTool, component: Component): BaseRef? {
    val base = edit.added ?: return null
    val old = edit.removed
    val struct = structOf(edit.owner)
    val part = embeddingOf(base)
    // Where the struct already holds it, else first for a first non-virtual base.
    val found = struct?.definedComponents?.firstOrNull { part != null && it.dataType.isEquivalent(part) }?.offset
    val offset = old?.offset ?: found?.toLong() ?: 0L.takeIf { edit.owner.bases.isEmpty() }

    // Virtual or not, access, and the offset to place the base at (blank: don't place it).
    return object : DialogComponentProvider("Add ${base.qualifiedName} as a base of ${edit.owner.qualifiedName}") {
        private val virtual = JCheckBox("Virtual", old?.isVirtual ?: false)
        private val accessBox = JComboBox(Access.entries.toTypedArray()).apply {
            selectedItem = old?.access ?: Access.PUBLIC
        }

        // Ghidra's own number field, hex to start with, a 0x prefix or its lack switching it; blank allowed.
        // setHexMode, deprecated in 12.2 for setFormat, is the one every Ghidra this builds for has.
        @Suppress("DEPRECATION")
        private val offsetField = IntegerTextField(10).apply {
            setAllowNegativeValues(false)
            maxValue = BigInteger.valueOf(Int.MAX_VALUE.toLong())
            setHexMode()
            setShowNumberMode(true)
            offset?.let(::setValue)
            setEnabled(struct != null)
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
                offsetField.value?.toLong()?.takeIf { struct != null },
            )
            close()
        }
    }.apply { tool.showDialog(this, component) }.result
}

private fun Component.confirm(title: String, message: String) =
    OptionDialog.showYesNoDialog(this, title, message) == OptionDialog.YES_OPTION

fun Program.applyEdits(edits: List<BaseEdit>, tool: PluginTool, component: Component) {
    for ((owner, removed, added) in edits) {
        val source = owner.solidSource() ?: continue
        val change = when (added) {
            null -> "remove ${removed?.name}"
            else -> "add ${added.qualifiedName}"
        }
        val ok = component.confirm(
            "Change ${owner.qualifiedName}'s bases",
            "${owner.qualifiedName}'s bases come from $source. ${change.replaceFirstChar(
                Char::uppercase,
            )} as a base anyway?",
        )
        if (!ok) return
    }
    val addition = edits.firstOrNull { it.added != null }
    val clause = addition?.let { askClause(it, tool, component) ?: return }
    val place = addition?.added?.let { base ->
        clause?.offset?.toInt()?.let { offset -> base to offset }
    }
    if (place != null) {
        val hit = overwrittenBy(addition.owner, place.first, place.second)
        val list = hit.joinToString("\n") {
            "  +0x%x %s".format(it.offset, it.fieldName ?: it.defaultFieldName)
        }
        if (hit.isNotEmpty() &&
            !component.confirm("Place ${place.first.qualifiedName}", "Placing it overwrites:\n$list\nGo on?")
        ) {
            return
        }
    }
    runCatching {
        runTransaction("Edit class hierarchy") {
            for (edit in edits) setBases(edit.owner, edit.bases(clause.takeIf { edit.added != null }))
            place?.let { (base, offset) ->
                val count = addition.bases(clause).size
                placeBase(addition.owner, base, offset, clause!!.isVirtual, count)
            }
        }
    }.onFailure {
        Msg.showError(this, component, "Edit Class Hierarchy", it.message, it)
    }.getOrNull()?.let {
        Msg.showWarn(this, component, "Edit Class Hierarchy", "The base wasn't placed: $it")
    }
}

fun Program.moveNamespace(h: ClassHierarchy, from: List<String>, to: List<String>, component: Component) {
    val ns = namespaceAt(from) ?: return
    val parent = namespaceAt(to) ?: return
    val named = h.classes.filter { it.path.startsWith(from) }
        .mapNotNull { c -> c.solidSource()?.let { "  ${c.qualifiedName}: $it" } }
    val what = from.joinToString("::")
    if (named.isNotEmpty() &&
        !component.confirm("Move $what", "These classes' names come from:\n${named.joinToString("\n")}\nMove anyway?")
    ) {
        return
    }
    runCatching {
        runTransaction("Move $what") { relocateNamespace(ns, parent) }
    }.onFailure {
        Msg.showError(this, component, "Move $what", it.message, it)
    }.getOrNull()?.let {
        Msg.showWarn(this, component, "Move $what", "Kept their old place:\n" + it.joinToString("\n"))
    }
}

fun Program.moveMembers(members: List<Member>, target: ClassInfo, component: Component) {
    val moving = members.filter { it !in target.members }
    val tied = moving.mapNotNull { m -> memberSource(m)?.let { "  ${m.label}: $it" } }
    if (tied.isNotEmpty() &&
        !component.confirm(
            "Move to ${target.qualifiedName}",
            "These say which class they belong to:\n${tied.joinToString("\n")}\nMove them anyway?",
        )
    ) {
        return
    }
    val failed = runTransaction("Move members to ${target.qualifiedName}") {
        moving.mapNotNull { m ->
            runCatching { moveMember(m, target) }.exceptionOrNull()?.let { "${m.label}: ${it.message}" }
        }
    }
    if (failed.isNotEmpty()) {
        Msg.showWarn(
            this,
            component,
            "Move Members",
            "Not moved:\n" + failed.joinToString("\n"),
        )
    }
}
