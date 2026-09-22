package ghistabs

import ghidra.framework.options.OptionType
import ghidra.framework.options.Options
import ghidra.util.HelpLocation
import java.beans.PropertyEditor
import java.util.function.Supplier

/**
 * The `Supplier<PropertyEditor>` overload 11.1 introduced, resolved eagerly onto the one that takes
 * the editor itself. Declared once per calling package because an extension is only visible
 * unqualified where it is declared — and a member beats an extension, so the pre-11.1 overload taking
 * the editor directly would otherwise win the call and reject the supplier.
 */
internal fun Options.registerOption(
    name: String,
    type: OptionType,
    defaultValue: Any?,
    help: HelpLocation?,
    description: String,
    editor: Supplier<PropertyEditor>?,
) = registerOption(name, type, defaultValue, help, description, editor?.get())
