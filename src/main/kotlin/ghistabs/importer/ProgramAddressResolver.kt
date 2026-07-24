package ghistabs.importer

import ghidra.app.util.opinion.ElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghistabs.diagnose.DiagnosticSink
import ghistabs.plus

interface AddressResolver {
    /** Where [stabAddress] tallies its relative/absolute branch counters. */
    val sink: DiagnosticSink
    fun buildAddress(offset: Long): Address
    fun resolve(name: String): Address?

    /**
     * Resolve a stab `n_value` that may be function-relative: block scopes and line numbers in
     * stabs-in-sections are offsets from [funcStart] (a genuine offset stays below it; an already
     * absolute value doesn't). Pass a null [funcStart] for records that are always absolute. Tallies
     * which branch it took on the resolver's [sink] (`stab-value-func-relative` vs `stab-value-absolute`).
     */
    fun stabAddress(value: Long, funcStart: Address?): Address = if (funcStart != null && value < funcStart.offset) {
        sink.debug("stab-value-func-relative")
        funcStart + value
    } else {
        sink.debug("stab-value-absolute")
        buildAddress(value)
    }
}

/**
 * Address resolver that searches program symbols and builds addresses in the default program address space.
 */
class ProgramAddressResolver(private val program: Program, override val sink: DiagnosticSink) : AddressResolver {
    // Stab values are link-time vaddrs. Ghidra relocates a PIE/ET_DYN ELF to its load
    // base (default 0x100000) without rewriting the stabs, so every address is off by
    // (loadBase - originalBase). PE has no such property → null → no fixup. Mirrors
    // Ghidra's own DWARF address fixup (DIEContainer.setProgramBaseAddressFixup).
    private val baseFixup: Long =
        ElfLoader.getElfOriginalImageBase(program)?.let { program.imageBase.offset - it } ?: 0L

    override fun buildAddress(offset: Long): Address =
        program.addressFactory.defaultAddressSpace.getAddress(offset) + baseFixup

    /**
     * Resolve [name]: symbol table → `_<name>` (MinGW/PE cdecl underscore prefix —
     * `Foo`→`_Foo`, `_ZTI4Foo`→`__ZTI4Foo`).
     */
    override fun resolve(name: String): Address? {
        program.symbolTable.getSymbols(name).firstOrNull()?.let { return it.address }
        program.symbolTable.getSymbols("_$name").firstOrNull()?.let { return it.address }
        return null
    }
}
