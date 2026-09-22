package ghidra.app.util.importer.options

import ghidra.app.util.Option

/**
 * The typed [Option] 12.2 (GP-6483) replaced `Option(name, value)` with. Below it, `Option` carries
 * an untyped value and the dialog builds the checkbox itself off [getValueClass], so the whole
 * backport is that class and the constructor shape.
 *
 * [Boolean.javaObjectType], not `Boolean::class.java`: the latter is `boolean.class`, which
 * `OptionsEditorPanel`'s `Boolean.class.isAssignableFrom` does not match.
 *
 * `stateKey` and `hidden` are carried but not passed down: the constructor taking them arrived in
 * 11, and nothing here sets either — the dialog reads them as null and false, which is what the
 * constructor this does use leaves behind.
 */
open class BooleanOption(
    name: String,
    value: Boolean,
    arg: String?,
    group: String?,
    private val stateKey: String?,
    private val hidden: Boolean,
    val description: String?,
) : Option(name, Boolean::class.javaObjectType, value, arg, group) {
    override fun copy() = BooleanOption(name, value as Boolean, arg, group, stateKey, hidden, description)
}
