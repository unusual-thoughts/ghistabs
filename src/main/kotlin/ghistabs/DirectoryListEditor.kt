package ghistabs

import docking.widgets.button.BrowseButton
import docking.widgets.filechooser.GhidraFileChooser
import docking.widgets.filechooser.GhidraFileChooserMode
import java.awt.Component
import java.beans.PropertyEditorSupport
import java.io.File
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JPanel
import javax.swing.JTextField
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

/**
 * Editor for a `;`-separated list of directories, [ImportOptions.SOURCE_ROOTS] being the one that has
 * one: the plain text field such an option would get anyway, plus a browse button whose chooser takes
 * **directories only**, multi-selects, and *appends* what it picked instead of replacing the field —
 * entries accumulate, and the field stays typeable.
 *
 * Ghidra's [docking.options.editor.FileChooserEditor] is the stock answer for a path-valued option
 * ([ghidra.app.plugin.core.analysis.ApplyDataArchiveAnalyzer] uses it), but it hardcodes
 * `FILES_AND_DIRECTORIES` and holds one path, so it can't express either half of this.
 */
class DirectoryListEditor(private val chooserTitle: String) : PropertyEditorSupport() {
    private val textField = JTextField(NUMBER_OF_COLUMNS)

    override fun getValue(): Any = asText

    override fun setValue(value: Any?) {
        asText = value as? String ?: ""
    }

    override fun getAsText(): String = textField.text.trim()

    override fun setAsText(text: String?) {
        textField.text = text.orEmpty()
    }

    override fun supportsCustomEditor() = true

    override fun getCustomEditor(): Component = JPanel().apply {
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        add(textField)
        add(Box.createHorizontalStrut(5))
        add(BrowseButton().also { browse -> browse.addActionListener { chooseDirs(browse) } })
        textField.addActionListener { firePropertyChange() }
        textField.document.addDocumentListener(
            object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent) = firePropertyChange()
                override fun removeUpdate(e: DocumentEvent) = firePropertyChange()
                override fun changedUpdate(e: DocumentEvent) = firePropertyChange()
            },
        )
    }

    private val roots get() = asText.split(';').map { it.trim() }.filter { it.isNotEmpty() }

    private fun chooseDirs(parent: Component) = GhidraFileChooser(parent).run {
        setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY)
        isMultiSelectionEnabled = true
        title = chooserTitle
        setApproveButtonText("Add")
        roots.lastOrNull()?.let(::File)?.parentFile?.let(::setCurrentDirectory)
        selectedFiles.map { it.absolutePath }.also { dispose() }
    }.let { chosen ->
        if (chosen.isNotEmpty()) asText = (roots + chosen).distinct().joinToString(";")
    }

    private companion object {
        const val NUMBER_OF_COLUMNS = 20
    }
}
