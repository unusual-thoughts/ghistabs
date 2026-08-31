package ghistabs

import ghidra.framework.options.OptionType
import ghidra.framework.options.Options
import ghidra.util.HelpLocation
import java.beans.PropertyEditor
import java.util.function.Supplier

/**
 * The `Supplier<PropertyEditor>` overload 11.1 introduced, resolved eagerly onto the one that takes
 * the editor itself. In [ghistabs] rather than Ghidra's package so the call site needs no import: an
 * extension is only visible unqualified from the package that declares it.
 */
internal fun Options.registerOption(
    name: String,
    type: OptionType,
    defaultValue: Any?,
    help: HelpLocation?,
    description: String,
    editor: Supplier<PropertyEditor>?,
) = registerOption(name, type, defaultValue, help, description, editor?.get())
