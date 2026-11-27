package ghidrakt
import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.MangledContext
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler

/**
 * `demangle(MangledContext)` unpacked onto the `(mangled, options)` overload it replaced. In
 * [ghidrakt] rather than Ghidra's package so the call site needs no import.
 */
internal fun GnuDemangler.demangle(context: MangledContext): DemangledObject =
    demangle(context.mangled, context.options)

/** The same for [MicrosoftDemangler]; its own options class only arrived with [MangledContext]. */
internal fun MicrosoftDemangler.demangle(context: MangledContext): DemangledObject =
    demangle(context.mangled, context.options)
