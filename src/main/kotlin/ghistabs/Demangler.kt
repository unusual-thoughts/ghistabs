package ghistabs

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.DemanglerOptions
import ghidra.app.util.demangler.DemanglerUtil
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

/**
 * Ghidra's C++ demangler in one place — the only module that touches DemanglerUtil / DemanglerCmd /
 * DemanglerOptions. Pure name-string parsing (namespace/template splitting, mangled classification)
 * lives Ghidra-free in `ghistabs.parse` (Names.kt).
 */

/** Demangle [mangled] to a [DemangledObject], or null if it isn't a mangled name / demangling fails. */
fun demangle(program: Program?, mangled: String, addr: Address? = null): DemangledObject? =
    runCatching { DemanglerUtil.demangle(program, mangled, addr).firstOrNull() }.getOrNull()

/** Human-readable name for [mangled], falling back to [fallback] (the mangled string by default). */
fun demangledName(program: Program?, mangled: String, addr: Address? = null, fallback: String = mangled): String =
    demangle(program, mangled, addr)?.demangledName ?: fallback

/** Parent-namespace chain, root-first, for [mangled] — or null if it has no enclosing namespace. */
fun namespaceChain(program: Program?, mangled: String): List<String>? {
    val parent = demangle(program, mangled)?.namespace ?: return null
    return generateSequence(parent) { it.namespace }.map { it.name }.toList().asReversed()
}

/**
 * Apply Ghidra's demangler to the symbol at [addr] (rename + namespace). Signature / calling-
 * convention / disassembly application are off by default — the stab carries richer types than the
 * mangled name. Returns whether the command applied.
 */
fun applyDemangling(
    program: Program,
    addr: Address,
    mangled: String,
    applySignature: Boolean = false,
    applyCallingConvention: Boolean = false,
    doDisassembly: Boolean = false,
    monitor: TaskMonitor? = null,
): Boolean {
    val options = DemanglerOptions().apply {
        setApplySignature(applySignature)
        setApplyCallingConvention(applyCallingConvention)
        setDoDisassembly(doDisassembly)
    }
    val cmd = DemanglerCmd(addr, mangled, options)
    val applied = if (monitor != null) cmd.applyTo(program, monitor) else cmd.applyTo(program)
    return applied && cmd.result != null
}
