package ghicpp.gui

import docking.ActionContext
import docking.action.DockingAction
import docking.action.MenuData
import docking.widgets.dialogs.InputDialog
import docking.widgets.dialogs.InputWithChoicesDialog
import ghicpp.ClassRecordSource
import ghicpp.hierarchy.ClassHierarchy
import ghicpp.hierarchy.SlotRenames
import ghicpp.hierarchy.VirtualSlots
import ghicpp.hierarchy.moveIntoClass
import ghicpp.hierarchy.slotDefinitionsOf
import ghidra.app.decompiler.ClangFieldToken
import ghidra.app.decompiler.ClangFuncNameToken
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.app.plugin.core.decompile.DecompilerActionContext
import ghidra.app.plugin.core.decompile.actions.AbstractDecompilerAction
import ghidra.framework.plugintool.Plugin
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.HelpLocation
import ghidra.util.Msg
import ghidra.util.task.MonitoredRunnable
import ghidra.util.task.TaskLauncher
import ghidrakt.*

// The decompiler's own popup groups: "Rename Field" is the variable group's third ("02"), "Rename Function"
// the function group's fifth ("04"). A subgroup sorts as a string, so "02a" lands right after "02".
private const val VARIABLE_GROUP = "2 - Variable Group"
private const val FUNCTION_GROUP = "1 - Function Group"

/**
 * The decompiler window's popup actions on classes: Rename Slot, beside Rename Field, on a call through a
 * vftable's field or on a virtual function's name, and Move Function into Class, beside Rename Function.
 */
internal fun Plugin.addDecompilerActions() {
    tool.addAction(renameSlotAction())
    tool.addAction(moveIntoClassAction())
}

/** The vftable field the cursor is on, as `vptr->f` shows it: its struct and offset in it. */
private fun DecompilerActionContext.slotField(): Pair<Structure, Int>? {
    val token = tokenAtCursor as? ClangFieldToken ?: return null
    val struct = AbstractDecompilerAction.getCompositeDataType(token) as? Structure ?: return null
    val field = struct.getComponentContaining(token.offset) ?: return null
    return (struct to token.offset).takeIf { (field.dataType as? Pointer)?.dataType is FunctionDefinition }
}

/**
 * The function whose name the cursor is on, a call's or the decompiled function's own, past a thunk Ghidra
 * made ([AbstractDecompilerAction]'s own `getFunction` does the same).
 */
private fun DecompilerActionContext.namedFunction(): Function? {
    val token = tokenAtCursor as? ClangFuncNameToken ?: return null
    var f = DecompilerUtils.getFunction(program, token)
    while (f != null && f.isThunk && f.symbol.source == SourceType.DEFAULT) f = f.getThunkedFunction(false)
    return f?.takeUnless { it.isExternal }
}

private fun ActionContext.decompiler() = (this as? DecompilerActionContext)?.takeUnless { it.isDecompiling }

private fun Plugin.renameSlotAction() = object : DockingAction("Rename Virtual Slot", name) {
    override fun actionPerformed(context: ActionContext) {
        val ctx = context.decompiler() ?: return
        val p = ctx.program
        val field = ctx.slotField()
        val func = if (field == null) ctx.namedFunction() ?: return else null
        val old = field?.let { (s, at) -> s.getComponentContaining(at)?.fieldName } ?: func?.name
        val dialog = InputDialog("Rename Virtual Slot", "New name:", old.orEmpty())
        tool.showDialog(dialog, ctx.componentProvider)
        val newName = dialog.value?.trim()?.takeUnless { dialog.isCanceled || it.isEmpty() || it == old } ?: return
        var done: Result<SlotRenames>? = null
        TaskLauncher.launchModal(
            "Rename Virtual Slot",
            MonitoredRunnable { monitor ->
                monitor.message = "Reading classes"
                val slots = VirtualSlots(p, ClassHierarchy.of(p, ClassRecordSource.describedElsewhere(p)))
                done = runCatching {
                    p.runTransaction("Rename virtual slot $old") {
                        field?.let { (s, at) -> slots.renameField(s, at, newName) }
                            ?: slots.rename(func!!, newName)
                    }
                }
            },
        )
        val renamed = done?.getOrElse {
            return Msg.showError(this, ctx.componentProvider.component, "Rename Virtual Slot", it.message)
        } ?: return
        tool.statusInfo = "Renamed ${renamed.functions} function(s) and ${renamed.fields} vftable slot(s)"
        if (renamed.skipped.isNotEmpty()) {
            Msg.showWarn(
                this,
                ctx.componentProvider.component,
                "Rename Virtual Slot",
                "Kept their old names:\n" + renamed.skipped.joinToString("\n"),
            )
        }
    }
}.apply {
    popupMenuData = MenuData(arrayOf("Rename Slot"), null, VARIABLE_GROUP, MenuData.NO_MNEMONIC, "02a")
    description = "Rename a vftable slot: its field in every class's table, and every function overriding it"
    helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
    validContextWhen { it is DecompilerActionContext }
    popupWhen { ctx ->
        ctx.decompiler()?.let { d ->
            d.slotField() != null || d.namedFunction()?.let { d.program.slotDefinitionsOf(it).isNotEmpty() } == true
        } == true
    }
}

private fun Plugin.moveIntoClassAction() = object : DockingAction("Move Function into Class", name) {
    override fun actionPerformed(context: ActionContext) {
        val ctx = context.decompiler() ?: return
        val func = ctx.namedFunction() ?: ctx.function ?: return
        val p = ctx.program
        val classes = p.classPaths()
        val current = (func.parentNamespace as? GhidraClass)?.getName(true).orEmpty()
        val dialog = InputWithChoicesDialog(
            "Move ${func.name} into Class",
            "Class (A::B, made where there is none):",
            classes.toTypedArray(),
            current,
            true,
            null,
        )
        tool.showDialog(dialog, ctx.componentProvider)
        val path = dialog.value?.trim()?.takeUnless { dialog.isCanceled || it.isEmpty() } ?: return
        runCatching { p.runTransaction("Move ${func.name} into $path") { p.moveIntoClass(func, path) } }
            .onSuccess { tool.statusInfo = "${func.name} is now a method of ${it.getName(true)}" }
            .onFailure { Msg.showError(this, ctx.componentProvider.component, "Move Function into Class", it.message) }
    }
}.apply {
    popupMenuData = MenuData(arrayOf("Move Function into Class..."), null, FUNCTION_GROUP, MenuData.NO_MNEMONIC, "04a")
    description = "Put the function in a class's namespace, and make it a __thiscall method taking that class's this"
    helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
    validContextWhen { it is DecompilerActionContext }
    popupWhen { ctx ->
        ctx.decompiler()?.let { d -> (d.namedFunction() ?: d.function)?.isExternal == false } == true
    }
}

/** Every class's path, `A::B`, sorted. */
private fun Program.classPaths(): List<String> =
    symbolTable.classNamespaces.asSequence().filterNot { it.isExternal }.map { it.getName(true) }.sorted().toList()
