package ghistabs.cpp.gui

import docking.DialogComponentProvider
import docking.widgets.OptionDialog
import docking.widgets.textfield.IntegerTextField
import ghidra.framework.plugintool.PluginTool
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.layout.PairLayout
import ghistabs.cpp.Access
import ghistabs.cpp.MemberAttrs
import ghistabs.cpp.MemberAttrs.Companion.writeMember
import ghistabs.cpp.VirtKind
import ghistabs.cpp.gui.ClassHierarchy.*
import ghistabs.namespaceAt
import ghistabs.runTransaction
import ghistabs.startsWith
import java.awt.Component
import java.math.BigInteger
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel

/** Asks how [edit]'s owner holds the base it gains; the clause it replaces, if any, gives the defaults. */
private fun Program.askClause(edit: BaseEdit, tool: PluginTool, component: Component): BaseRef? {
    val base = edit.added ?: return null
    val old = edit.removed
    val struct = structOf(edit.of)
    val part = embeddingOf(base)
    // Where the struct already holds it, else first for a first non-virtual base.
    val found = struct?.definedComponents?.firstOrNull { part != null && it.dataType.isEquivalent(part) }?.offset
    val offset = old?.offset ?: found?.toLong() ?: 0L.takeIf { edit.of.bases.isEmpty() }

    // Virtual or not, access, and the offset to place the base at (blank: don't place it).
    return object : DialogComponentProvider("Add ${base.qualifiedName} as a base of ${edit.of.qualifiedName}") {
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
                JPanel(PairLayout(4, 8)).apply {
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
        val hit = overwrittenBy(addition.of, place.first, place.second)
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
            for (edit in edits) setBases(edit.of, edit.bases(clause.takeIf { edit.added != null }))
            place?.let { (base, offset) ->
                val count = addition.bases(clause).size
                placeBase(addition.of, base, offset, clause!!.isVirtual, count)
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

/**
 * Asks how [member] is declared in [target]: access, virtuality, cv for a function; access alone for a
 * static data member. What it had gives the defaults. With [more] members to go, it can answer for them too.
 */
private fun askMemberAttrs(
    member: Member,
    target: ClassInfo,
    more: Boolean,
    tool: PluginTool,
    component: Component,
): Pair<MemberAttrs, Boolean>? {
    val old = member.attrs ?: MemberAttrs()
    val function = member.kind == MemberKind.FUNCTION
    return object : DialogComponentProvider("Declare ${member.label} in ${target.qualifiedName}") {
        private val unknown = "unknown"
        private val accessBox = JComboBox<Any>((listOf<Any>(unknown) + Access.entries).toTypedArray()).apply {
            selectedItem = old.access ?: unknown
        }
        private val virtBox = JComboBox(VirtKind.entries.toTypedArray()).apply {
            selectedItem = old.virt ?: VirtKind.NORMAL
        }
        private val constBox = JCheckBox("const", old.isConst)
        private val volatileBox = JCheckBox("volatile", old.isVolatile)
        private val forRest = JCheckBox("The same for the other members moved", false)
        var result: Pair<MemberAttrs, Boolean>? = null
            private set

        init {
            addWorkPanel(
                JPanel(PairLayout(4, 8)).apply {
                    add(JLabel("Access:"))
                    add(accessBox)
                    if (function) {
                        add(JLabel("Kind:"))
                        add(virtBox)
                        add(JLabel("Qualifiers:"))
                        add(
                            JPanel().apply {
                                add(constBox)
                                add(volatileBox)
                            },
                        )
                    }
                    if (more) {
                        add(JLabel())
                        add(forRest)
                    }
                },
            )
            addOKButton()
            addCancelButton()
        }

        override fun okCallback() {
            val attrs = MemberAttrs(
                access = accessBox.selectedItem as? Access,
                virt = if (function) virtBox.selectedItem as VirtKind else VirtKind.STATIC,
                isConst = function && constBox.isSelected,
                isVolatile = function && volatileBox.isSelected,
            )
            result = attrs to forRest.isSelected
            close()
        }
    }.apply { tool.showDialog(this, component) }.result
}

fun Program.moveMembers(members: List<Member>, target: ClassInfo, tool: PluginTool, component: Component) {
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
    // How each is declared there, asked before anything moves; Cancel moves none.
    val declared = mutableMapOf<Member, MemberAttrs>()
    val same = mutableMapOf<MemberKind, MemberAttrs>()
    val asked = moving.filter { it.kind == MemberKind.FUNCTION || it.kind == MemberKind.LABEL }
    for ((i, m) in asked.withIndex()) {
        declared[m] = same[m.kind] ?: run {
            val more = asked.drop(i + 1).any { it.kind == m.kind }
            val (attrs, forRest) = askMemberAttrs(m, target, more, tool, component) ?: return
            attrs.also { if (forRest) same[m.kind] = it }
        }
    }
    val failed = runTransaction("Move members to ${target.qualifiedName}") {
        moving.mapNotNull { m ->
            runCatching {
                moveMember(m, target)
                declared[m]?.let { attrs -> addressFactory.getAddress(m.address)?.let { writeMember(it, attrs) } }
            }.exceptionOrNull()?.let { "${m.label}: ${it.message}" }
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
