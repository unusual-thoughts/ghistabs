package ghidra.app.util.importer.options

import ghidra.app.util.AddressFactoryService
import ghidra.app.util.Option
import java.awt.Component

/**
 * The typed [Option] 12.2 (GP-6483) replaced `Option(name, value)` with, and with it the editor hook
 * that release re-signed: 12.2 hands `getCustomEditorComponent` an [AddressFactoryService], for the
 * address-valued options that need a factory to parse against, where before it took nothing. An
 * override matches one signature or the other and never both, so the new one is declared here and
 * the old one routed onto it — which is what lets a subclass spell the override the 12.2 way.
 *
 * The text-field editor 12.2's own [StringOption] supplies is not backported: below 12.2 a plain
 * string option had none either, and every string option published to a dialog here overrides the
 * hook anyway. `stateKey` and `hidden` are carried but not passed down — see [BooleanOption].
 */
open class StringOption(
    name: String,
    value: String,
    arg: String?,
    group: String?,
    private val stateKey: String?,
    private val hidden: Boolean,
    val description: String?,
) : Option(name, String::class.java, value, arg, group) {
    override fun getValue() = super.getValue() as String

    override fun copy() = StringOption(name, value, arg, group, stateKey, hidden, description)

    open fun getCustomEditorComponent(addressFactoryService: AddressFactoryService?): Component? = null

    final override fun getCustomEditorComponent(): Component? = getCustomEditorComponent(null)
}
