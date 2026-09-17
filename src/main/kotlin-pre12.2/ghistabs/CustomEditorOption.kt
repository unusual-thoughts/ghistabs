package ghistabs

import ghidra.app.util.Option
import java.awt.Component

/**
 * Pre-12.2: `getCustomEditorComponent` takes nothing. 12.2 hands it an
 * `ghidra.app.util.AddressFactoryService`, and an override matches one signature or the other — never
 * both — so the whole point of this class is to absorb that difference and leave subclasses one
 * argument-free [editorComponent] to implement.
 */
abstract class CustomEditorOption(name: String, value: Any) : Option(name, value) {
    /** The editor, built on first display — see the subclass for why that matters headless. */
    protected abstract fun editorComponent(): Component

    override fun getCustomEditorComponent(): Component = editorComponent()
}
