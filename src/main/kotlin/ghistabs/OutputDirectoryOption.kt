package ghistabs

import docking.widgets.filechooser.GhidraFileChooserMode
import docking.widgets.filechooser.GhidraFileChooserPanel
import ghidra.app.util.Option
import java.awt.Component

/**
 * An export [Option] that renders as a **directories-only** chooser — the export dialog's own browse
 * button is `FILES_ONLY` and out of reach, so this is where [StabsDecompExporter] picks up a folder.
 * Empty by default, so the exporter falls back to the dialog's path.
 *
 * Same shape as [ghidra.app.util.exporter.IntelHexExporter]'s record-size option: the component
 * holds the value, and [getValue] reads it back out. Built on first display rather than in the
 * constructor, so a headless export never touches Swing.
 */
class OutputDirectoryOption(name: String, private val initial: String) : Option(name, initial) {
    private var panel: GhidraFileChooserPanel? = null

    override fun getCustomEditorComponent(): Component = panel ?: GhidraFileChooserPanel(
        name,
        "Stabs.LastExportDirectory",
        initial,
        false,
        GhidraFileChooserPanel.OUTPUT_MODE,
    ).apply { setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY) }.also { panel = it }

    override fun getValue(): Any = panel?.fileName?.trim() ?: initial

    override fun getValueClass(): Class<*> = String::class.java

    override fun copy(): Option = OutputDirectoryOption(name, value as String)
}
