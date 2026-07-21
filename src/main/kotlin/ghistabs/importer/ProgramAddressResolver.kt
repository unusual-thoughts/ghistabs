package ghistabs.importer

import ghidra.app.util.opinion.ElfLoader
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.plus

interface AddressResolver {
    /** Where [stabAddress] tallies its relative/absolute branch counters. */
    val sink: DiagnosticSink
    fun buildAddress(offset: Long): Address
    fun resolve(name: String): Address?
    fun recordFromStab(name: String, addr: Address): Boolean
}

/**
 * Resolve a stab `n_value` that may be function-relative: block scopes and line numbers in
 * stabs-in-sections are offsets from [funcStart] (a genuine offset stays below it; an already
 * absolute value doesn't). Pass a null [funcStart] for records that are always absolute. Tallies
 * which branch it took on the resolver's [sink] (`stab-value-func-relative` vs `stab-value-absolute`).
 */
fun AddressResolver.stabAddress(value: Long, funcStart: Address?): Address =
    if (funcStart != null && value < funcStart.offset) {
        sink.debug("stab-value-func-relative")
        funcStart + value
    } else {
        sink.debug("stab-value-absolute")
        buildAddress(value)
    }

open class StabOnlyAddressResolver : AddressResolver {
    override val sink: DiagnosticSink = DummySink
    private val stabMap: MutableMap<String, Address> = mutableMapOf()

    override fun buildAddress(offset: Long): Address =
        GenericAddressSpace("generic", 8, AddressSpace.TYPE_RAM, 0).getAddress(offset)

    override fun resolve(name: String) = stabMap[name]

    override fun recordFromStab(name: String, addr: Address): Boolean {
        if (name.isBlank()) {
            return false
        }
        val existing = stabMap[name]
        if (existing == null) {
            stabMap[name] = addr
        }
        if (existing != addr) {
            // Same name at two different addresses across CUs — keep first; caller logs.
            return false
        }
        return true
    }
}

/**
 * Address resolver that creates IMPORTED labels at stab-derived addresses.
 * **Caller must hold a Program transaction** — [recordFromStab] calls `createLabel`.
 */
class ProgramAddressResolver(private val program: Program, override val sink: DiagnosticSink) :
    StabOnlyAddressResolver() {
    override fun recordFromStab(name: String, addr: Address): Boolean {
        if (super.recordFromStab(name, addr)) {
            val present = program.symbolTable.getSymbols(addr).any { it.name == name }
            if (!present) {
                program.symbolTable.createLabel(addr, name, SourceType.IMPORTED)
            }
        }
        return true
    }

    // Stab values are link-time vaddrs. Ghidra relocates a PIE/ET_DYN ELF to its load
    // base (default 0x100000) without rewriting the stabs, so every address is off by
    // (loadBase - originalBase). PE has no such property → null → no fixup. Mirrors
    // Ghidra's own DWARF address fixup (DIEContainer.setProgramBaseAddressFixup).
    private val baseFixup: Long =
        ElfLoader.getElfOriginalImageBase(program)?.let { program.imageBase.offset - it } ?: 0L

    override fun buildAddress(offset: Long): Address =
        program.addressFactory.defaultAddressSpace.getAddress(offset) + baseFixup

    /**
     * Resolve [name]: stab map → symbol table → `_<name>` (MinGW/PE cdecl underscore prefix —
     * `Foo`→`_Foo`, `_ZTI4Foo`→`__ZTI4Foo`).
     */
    override fun resolve(name: String): Address? {
        super.resolve(name)?.let { return it }
        program.symbolTable.getSymbols(name).firstOrNull()?.let { return it.address }
        program.symbolTable.getSymbols("_$name").firstOrNull()?.let { return it.address }
        return null
    }
}
