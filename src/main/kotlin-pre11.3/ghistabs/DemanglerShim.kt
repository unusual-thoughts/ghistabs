package ghistabs

import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.MangledContext
import ghidra.app.util.demangler.gnu.GnuDemangler

/**
 * `demangle(MangledContext)` unpacked onto the `(mangled, options)` overload it replaced. In
 * [ghistabs] rather than Ghidra's package so the call site needs no import.
 */
internal fun GnuDemangler.demangle(context: MangledContext): DemangledObject =
    demangle(context.mangled, context.options)
