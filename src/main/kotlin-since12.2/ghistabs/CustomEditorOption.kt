package ghistabs

import ghidra.app.util.AddressFactoryService
import ghidra.app.util.Option
import java.awt.Component

/**
 * 12.2+ (GP-6483, the loader option redesign): `getCustomEditorComponent` is handed an
 * [AddressFactoryService], for the address-valued options that need a factory to parse against. A
 * directory picker does not, so it is dropped here and subclasses implement the argument-free
 * [editorComponent].
 *
 * 12.2 because that is the cycle the change landed in; no 12.2 was released — master bumped straight
 * to 12.3 — so in practice the first install selecting this file is a 12.3 DEV build.
 */
abstract class CustomEditorOption(name: String, value: Any) : Option(name, value) {
    /** The editor, built on first display — see the subclass for why that matters headless. */
    protected abstract fun editorComponent(): Component

    override fun getCustomEditorComponent(addressFactoryService: AddressFactoryService?): Component = editorComponent()
}
