package ghidra.app.util.demangler

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

/**
 * The context object 11.3 introduced to carry what `demangle` previously took as arguments. Only
 * [mangled] and [options] are ever populated here; the program and address exist so the call site
 * spells the constructor the same way on either release.
 */
class MangledContext(val program: Program?, val options: DemanglerOptions, val mangled: String, val address: Address?)
