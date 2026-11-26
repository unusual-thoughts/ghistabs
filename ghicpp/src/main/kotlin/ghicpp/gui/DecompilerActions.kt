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
import ghicpp.hierarchy.applySignatureToSlots
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
 * The decompiler window's popup actions on classes. Beside Rename Field, on a call through a vftable's field or
 * on a virtual function's name: Rename Slot, Update Slot Name and Update Slot Signature, as the class tree's
 * Rename Virtual Slot, Apply Slot Names to Vftables and Apply Signature to Vftables. Beside Rename Function: Move
 * Function into Class.
 */
internal fun Plugin.addDecompilerActions() {
    tool.addAction(renameSlotAction())
    tool.addAction(updateSlotNameAction())
    tool.addAction(updateSlotSignatureAction())
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
        val field = ctx.slotField()
        val func = if (field == null) ctx.namedFunction() ?: return else null
        val old = field?.let { (s, at) -> s.getComponentContaining(at)?.fieldName } ?: func?.name
        val dialog = InputDialog("Rename Virtual Slot", "New name:", old.orEmpty())
        tool.showDialog(dialog, ctx.componentProvider)
        val newName = dialog.value?.trim()?.takeUnless { dialog.isCanceled || it.isEmpty() || it == old } ?: return
        val renamed = ctx.withSlots("Rename Virtual Slot", "Rename virtual slot $old") { slots ->
            field?.let { (s, at) -> slots.renameField(s, at, newName) } ?: slots.rename(func!!, newName)
        } ?: return
        tool.statusInfo = "Renamed ${renamed.functions} function(s) and ${renamed.fields} vftable slot(s)"
        ctx.warnSkipped("Rename Virtual Slot", renamed)
    }
}.apply {
    popupMenuData = MenuData(arrayOf("Rename Slot"), null, VARIABLE_GROUP, MenuData.NO_MNEMONIC, "02a")
    description = "Rename a vftable slot: its field in every class's table, and every function overriding it"
    helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
    validContextWhen { it is DecompilerActionContext }
    popupWhen { it.onSlot() }
}

/** Whether the cursor is on a vftable's field ([slotField]) or a virtual function's name. */
private fun ActionContext.onSlot() = decompiler()?.let { d ->
    d.slotField() != null || d.namedFunction()?.let { d.program.slotDefinitionsOf(it).isNotEmpty() } == true
} == true

/**
 * Runs [edit] on the program's [VirtualSlots], read in a modal task, in a transaction named [transaction]: what it
 * returns, or null after showing what it threw, titled [title].
 */
private fun <T> DecompilerActionContext.withSlots(title: String, transaction: String, edit: (VirtualSlots) -> T): T? {
    val p = program
    var done: Result<T>? = null
    TaskLauncher.launchModal(
        title,
        MonitoredRunnable { monitor ->
            monitor.message = "Reading classes"
            done = runCatching {
                val slots = VirtualSlots(p, ClassHierarchy.of(p, ClassRecordSource.describedElsewhere(p)))
                p.runTransaction(transaction) { edit(slots) }
            }
        },
    )
    return done?.getOrElse {
        Msg.showError(this, componentProvider.component, title, it.message)
        null
    }
}

/** Warns of the names [done] kept, if any. */
private fun DecompilerActionContext.warnSkipped(title: String, done: SlotRenames) {
    if (done.skipped.isEmpty()) return
    Msg.showWarn(this, componentProvider.component, title, "Kept their old names:\n" + done.skipped.joinToString("\n"))
}

/**
 * Update Slot Name: names each vftable slot holding the virtual function under the cursor after it, or, on a
 * vftable's field, that slot in each table laid with its struct after the function that table holds there.
 */
private fun Plugin.updateSlotNameAction() = object : DockingAction("Update Virtual Slot Name", name) {
    override fun actionPerformed(context: ActionContext) {
        val ctx = context.decompiler() ?: return
        val field = ctx.slotField()
        val func = if (field == null) ctx.namedFunction() ?: return else null
        val done = ctx.withSlots("Update Slot Name", "Apply slot names to vftables") { slots ->
            slots.applyNames(field?.let { (s, at) -> slots.slotsAt(s, at) } ?: slots.slotsOf(func!!))
        } ?: return
        tool.statusInfo = "Named ${done.fields} vftable slot(s)"
        ctx.warnSkipped("Update Slot Name", done)
    }
}.apply {
    popupMenuData = MenuData(arrayOf("Update Slot Name"), null, VARIABLE_GROUP, MenuData.NO_MNEMONIC, "02b")
    description = "Name the vftable slot after the function it holds, in every table holding it"
    helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
    validContextWhen { it is DecompilerActionContext }
    popupWhen { it.onSlot() }
}

/**
 * Update Slot Signature: copies the virtual function's signature under the cursor into the function definition
 * its slots are typed with, or, on a vftable's field, that of each function the tables laid with its struct hold
 * there.
 */
private fun Plugin.updateSlotSignatureAction() = object : DockingAction("Update Virtual Slot Signature", name) {
    override fun actionPerformed(context: ActionContext) {
        val ctx = context.decompiler() ?: return
        val field = ctx.slotField()
        val func = if (field == null) ctx.namedFunction() ?: return else null
        val changed = ctx.withSlots("Update Slot Signature", "Apply signature to vftables") { slots ->
            val funcs = field?.let { (s, at) -> slots.slotsAt(s, at).mapNotNull(slots::target).distinct() }
                ?: listOf(func!!)
            funcs.sumOf { ctx.program.applySignatureToSlots(it) }
        } ?: return
        tool.statusInfo = "Applied the signature to $changed vftable slot definition(s)"
    }
}.apply {
    popupMenuData = MenuData(arrayOf("Update Slot Signature"), null, VARIABLE_GROUP, MenuData.NO_MNEMONIC, "02c")
    description = "Type the vftable slot with the signature of the function it holds, in every table holding it"
    helpLocation = HelpLocation("Stabs", "Stabs_Class_Hierarchy")
    validContextWhen { it is DecompilerActionContext }
    popupWhen { it.onSlot() }
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
