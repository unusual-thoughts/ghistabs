package ghidra.app.util.importer.options

import ghidra.app.util.Option

/**
 * The typed [Option] 12.2 (GP-6483) replaced `Option(name, value)` with. Below it, `Option` carries
 * an untyped value and the dialog builds the checkbox itself off [getValueClass], so the whole
 * backport is that class and the constructor shape.
 *
 * [Boolean.javaObjectType], not `Boolean::class.java`: the latter is `boolean.class`, which
 * `OptionsEditorPanel`'s `Boolean.class.isAssignableFrom` does not match.
 */
open class BooleanOption(
    name: String,
    value: Boolean,
    arg: String?,
    group: String?,
    stateKey: String?,
    hidden: Boolean,
    val description: String?,
) : Option(name, Boolean::class.javaObjectType, value, arg, group, stateKey, hidden) {
    override fun copy() = BooleanOption(name, value as Boolean, arg, group, stateKey, isHidden, description)
}
