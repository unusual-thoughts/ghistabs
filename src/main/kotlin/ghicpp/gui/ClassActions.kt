package ghicpp.gui

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.action.ToggleDockingAction
import docking.action.ToolBarData
import docking.widgets.dialogs.InputDialog
import generic.theme.GIcon
import ghicpp.hierarchy.ClassHierarchy.*
import ghicpp.hierarchy.applySignatureToSlots
import ghicpp.hierarchy.relocateNamespace
import ghicpp.hierarchy.renameClass
import ghicpp.hierarchy.resolve
import ghicpp.hierarchy.slotDefinitionsOf
import ghicpp.hierarchy.updateFieldTypes
import ghidra.app.cmd.label.SetLabelPrimaryCmd
import ghidra.app.context.ProgramSymbolActionContext
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService
import ghidra.app.plugin.core.symboltree.actions.ClearPinSymbolAction
import ghidra.app.plugin.core.symboltree.actions.PinSymbolAction
import ghidra.app.services.CodeViewerService
import ghidra.app.services.DataTypeManagerService
import ghidra.app.util.AddEditDialog
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.VariableUtilities
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolType
import ghidra.program.util.FunctionSignatureFieldLocation
import ghidra.util.HTMLUtilities
import ghidra.util.HelpLocation
import ghidra.util.Msg
import ghidra.util.task.MonitoredRunnable
import ghidra.util.task.TaskLauncher
import ghistabs.namespaceAt
import ghistabs.runTransaction
import resources.Icons

private val STRUCT_ICON = GIcon("icon.plugin.datatypes.structure")
private val VTABLE_ICON = GIcon("icon.plugin.navigation.bytes")

/**
 * The popup actions on the selection: a class's struct and vtable, renames, field types, a member's
 * overridden function and attributes, and the Symbol Tree's own actions on a member's symbol. The
 * toolbar's are below ([addToolbarActions]).
 */
internal fun ClassTree.addSelectionActions() {
    addClassActions()
    addMemberActions()
    addSymbolActions()
}

/** The popup actions on the selected class or namespace: its structs, its name, its field types. */
private fun ClassTree.addClassActions() {
    addLocalAction(
        object : DockingAction("Edit class struct", owner) {
            override fun actionPerformed(context: ActionContext?) {
                val cls = selectedClass ?: return
                (cls.structId ?: createStruct(cls))?.let { openStruct(it) }
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Edit class struct"), STRUCT_ICON)
            popupWhen {
                selectedClass?.let { it.structId != null || it.origin != Origin.IMPORTED } ==
                    true
            }
        },
    )
    addLocalAction(
        object : DockingAction("Rename Class", owner) {
            override fun actionPerformed(context: ActionContext?) {
                selectedClass?.let(::renameSelected)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Rename Class"), "0")
            popupWhen { selectedClass?.let { it.origin != Origin.IMPORTED } == true }
        },
    )
    addLocalAction(
        object : DockingAction("Rename Namespace", owner) {
            override fun actionPerformed(context: ActionContext?) {
                (selectedNode as? NamespaceNode)?.let(::renameNamespace)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Rename Namespace"), "0")
            popupWhen { selectedNode is NamespaceNode }
        },
    )
    addLocalAction(
        object : DockingAction("Edit vtable struct", owner) {
            override fun actionPerformed(context: ActionContext?) {
                selectedClass?.vftableStructId?.let { openStruct(it) }
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Edit vtable struct"), VTABLE_ICON)
            popupWhen { selectedClass?.vftableStructId != null }
        },
    )
    addLocalAction(
        object : DockingAction("Update Class Field Types", owner) {
            override fun actionPerformed(context: ActionContext?) {
                selectedClass?.let { updateFieldTypes(listOf(it to null)) }
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Update Field Types"), STRUCT_ICON)
            popupWhen { selectedClass?.let { it.structId != null && it.origin != Origin.IMPORTED } == true }
        },
    )
}

/** The popup actions on the selected members: their field types, the function overridden, their attributes. */
private fun ClassTree.addMemberActions() {
    addLocalAction(
        object : DockingAction("Update Field Types from Method", owner) {
            override fun actionPerformed(context: ActionContext?) {
                updateFieldTypes(selectedMembers.groupBy({ it.second }, { it.first }).toList())
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Update Field Types"), STRUCT_ICON)
            popupWhen {
                selectedMembers.let { sel ->
                    sel.isNotEmpty() &&
                        sel.all { (m, cls) -> m.kind == MemberKind.FUNCTION && cls.structId != null }
                }
            }
        },
    )
    addLocalAction(
        object : DockingAction("Apply Signature to Vftables", owner) {
            override fun actionPerformed(context: ActionContext?) {
                val p = program ?: return
                val funcs = selectedFunctions()
                val changed = p.runTransaction("Apply signature to vftables") {
                    funcs.sumOf { p.applySignatureToSlots(it) }
                }
                tool.setStatusInfo("Applied ${funcs.size} signature(s) to $changed vftable slot definition(s)")
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Apply Signature to Vftables"), VTABLE_ICON)
            popupWhen {
                selectedFunctions().let { fs ->
                    fs.isNotEmpty() &&
                        fs.all { program?.slotDefinitionsOf(it)?.isNotEmpty() == true }
                }
            }
        },
    )
    addLocalAction(
        object : DockingAction("Go to Overridden", owner) {
            override fun actionPerformed(context: ActionContext?) {
                goTo(selectedOverridden?.address)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Go to Overridden"), "0")
            popupWhen { selectedMember?.kind == MemberKind.FUNCTION }
            enabledWhen { selectedOverridden != null }
        },
    )
    addLocalAction(
        object : DockingAction("Set Member Attributes", owner) {
            override fun actionPerformed(context: ActionContext?) {
                program?.setMemberAttrs(selectedMembers, tool, component)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Set Member Attributes..."), "0")
            popupWhen { selectedMembers.let { it.isNotEmpty() && it.all { (m, _) -> m.takesAttrs } } }
        },
    )
}

/**
 * The Symbol Tree's actions on a member's symbol. Not on a class's: renaming or deleting its namespace
 * would part it from its struct and the stabs record.
 */
private fun ClassTree.addSymbolActions() {
    val group = "1"
    addLocalAction(
        object : DockingAction("Rename Class Member", owner) {
            override fun actionPerformed(context: ActionContext) {
                val symbol = memberSymbols(context).single()
                AddEditDialog("Rename", tool).editLabel(symbol, symbol.program, this@addSymbolActions)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Rename"), group)
            popupWhen { memberSymbols(it).size == 1 }
        },
    )
    addLocalAction(
        object : DockingAction("Delete Class Members", owner) {
            override fun actionPerformed(context: ActionContext) {
                val symbols = memberSymbols(context)
                symbols.first().program.runTransaction("Delete Symbol(s)") { symbols.forEach(Symbol::delete) }
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Delete"), Icons.DELETE_ICON, group)
            popupWhen { memberSymbols(it).isNotEmpty() }
        },
    )
    addLocalAction(
        object : DockingAction("Show References to Class Member", owner) {
            override fun actionPerformed(context: ActionContext) {
                val symbol = memberSymbols(context).single()
                // A function's, at its signature, as the Symbol Tree has them: else only its entry's.
                val at = if (symbol.symbolType == SymbolType.FUNCTION) {
                    FunctionSignatureFieldLocation(symbol.program, symbol.address)
                } else {
                    symbol.programLocation
                }
                tool.getService(LocationReferencesService::class.java)
                    ?.showReferencesToLocation(at, tool.getService(CodeViewerService::class.java)?.navigatable)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Show References to"), "2")
            popupWhen {
                memberSymbols(it).size == 1 && tool.getService(LocationReferencesService::class.java) != null
            }
        },
    )
    // Ghidra's own SetSymbolPrimaryAction is 12.0's.
    addLocalAction(
        object : DockingAction("Set Class Member Primary", owner) {
            override fun actionPerformed(context: ActionContext) {
                val symbol = memberSymbols(context).single()
                val cmd = SetLabelPrimaryCmd(symbol.address, symbol.name, symbol.parentNamespace)
                if (!tool.execute(cmd, symbol.program)) Msg.showError(this, component, "Set Primary", cmd.statusMsg)
            }
        }.apply {
            popupMenuData = MenuData(arrayOf("Set Primary"), "2")
            popupWhen { memberSymbols(it).singleOrNull()?.isPrimary == false }
        },
    )
    addLocalAction(PinSymbolAction(owner, "2"))
    addLocalAction(ClearPinSymbolAction(owner, "2"))
}

/** The context's symbols, when they are all members': none else. */
private fun memberSymbols(context: ActionContext): List<Symbol> =
    (context as? ProgramSymbolActionContext)?.symbols?.toList().orEmpty()
        .takeIf { all -> all.all { it.symbolType == SymbolType.FUNCTION || it.symbolType == SymbolType.LABEL } }
        .orEmpty()

/**
 * Retypes each class's fields off the methods paired with it, or off all its own when null, decompiling
 * them in a task that can be cancelled: what it retyped before then stays.
 */
private fun ClassTree.updateFieldTypes(targets: List<Pair<ClassView, List<Member>?>>) {
    val p = program ?: return
    TaskLauncher.launchModal(
        "Update Field Types",
        MonitoredRunnable { monitor ->
            p.runTransaction("Update field types") {
                for ((cls, methods) in targets) {
                    if (!monitor.isCancelled) p.updateFieldTypes(cls, methods, monitor)
                }
            }
        },
    )
}

/** The selected members' functions, when they are all functions. */
private fun ClassTree.selectedFunctions(): List<Function> {
    val p = program ?: return emptyList()
    return selectedMembers.map { (m, _) ->
        m.takeIf { it.kind == MemberKind.FUNCTION }
            ?.let { p.addressFactory.getAddress(it.address) }
            ?.let(p.functionManager::getFunctionAt) ?: return emptyList()
    }
}

/** A struct for [cls], which has none, where Ghidra files a class's; its datatype id. */
private fun ClassTree.createStruct(cls: ClassView): Long? {
    val program = program ?: return null
    val ns = program.resolve(cls) ?: return null
    val dtm = program.dataTypeManager
    return program.runTransaction("Create class struct") {
        val struct = VariableUtilities.findOrCreateClassStruct(ns, dtm)
        dtm.getID(dtm.resolve(struct, DataTypeConflictHandler.DEFAULT_HANDLER))
    }
}

/** Ask for [cls]'s new name, then [renameClass]: a name Ghidra refuses changes nothing. */
private fun ClassTree.renameNamespace(node: NamespaceNode) {
    val p = program ?: return
    val ns = p.namespaceAt(node.path) ?: return
    val dialog = InputDialog("Rename Namespace", "New name:", ns.name)
    tool.showDialog(dialog, this)
    val name = dialog.value?.trim()?.takeUnless { dialog.isCanceled || it.isEmpty() || it == ns.name } ?: return
    val skipped = runCatching {
        p.runTransaction("Rename namespace ${ns.name}") { p.relocateNamespace(ns, ns.parentNamespace, name) }
    }.onFailure { Msg.showError(this, component, "Rename Namespace", it.message, it) }.getOrNull()
    if (!skipped.isNullOrEmpty()) {
        Msg.showWarn(this, component, "Rename Namespace", "Kept their old place:\n" + skipped.joinToString("\n"))
    }
}

private fun ClassTree.renameSelected(cls: ClassView) {
    val p = program ?: return
    val h = shown ?: return
    val dialog = InputDialog("Rename Class", "New name:", cls.name)
    tool.showDialog(dialog, this)
    val name = dialog.value?.trim()?.takeUnless { dialog.isCanceled || it.isEmpty() || it == cls.name } ?: return
    val skipped = runCatching { p.runTransaction("Rename class ${cls.name}") { p.renameClass(h, cls, name) } }
        .getOrElse { return Msg.showError(this, component, "Rename Class", it.message) }
    if (skipped.isNotEmpty()) {
        Msg.showWarn(this, component, "Rename Class", "Kept their old names:\n" + skipped.joinToString("\n"))
    }
}

private fun ClassTree.openStruct(id: Long) = program?.apply {
    dataTypeManager.getDataType(id)?.let {
        tool.getService(DataTypeManagerService::class.java)?.edit(it)
    }
}

/** The window's toolbar: Refresh, and the toggles for what the tree shows and how it follows the listing. */
internal fun ClassTree.addToolbarActions() {
    addViewToggles()
    addDirectionAndNavigateToggles()
}

/** Refresh, and what the tree shows: members, empty classes, everything expanded. */
private fun ClassTree.addViewToggles() {
    addLocalAction(
        object : DockingAction("Refresh Class Hierarchy", owner) {
            override fun actionPerformed(context: ActionContext?) = rebuild()
        }.apply {
            toolBarData = ToolBarData(Icons.REFRESH_ICON, null)
            description = "Rebuild the class hierarchy from the program"
            helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
        },
    )
    addLocalAction(
        object : ToggleDockingAction("Show Class Members", owner) {
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
        object : ToggleDockingAction("Show Empty Classes", owner) {
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
        object : ToggleDockingAction("Expand All Classes", owner) {
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
}

/** Which way the tree runs, and whether it follows the listing and the listing it. */
private fun ClassTree.addDirectionAndNavigateToggles() {
    addLocalAction(
        object : ToggleDockingAction("Show Derived Classes", owner) {
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
        object : ToggleDockingAction("Navigate on Incoming", owner) {
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
        object : ToggleDockingAction("Navigate on Outgoing", owner) {
            override fun actionPerformed(context: ActionContext?) {
                if (isSelected) openSelected()
            }
        }.apply {
            toolBarData = ToolBarData(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, null)
            description = HTMLUtilities.toHTML(
                "Toggle <b>On</b> means to go to the selected member\nor class in the program",
            )
            isSelected = true
            helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
        }.also { navigateOutgoing = it },
    )
}
