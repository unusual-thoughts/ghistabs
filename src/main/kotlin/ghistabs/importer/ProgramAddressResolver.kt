package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.address.GenericAddressSpace
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType

interface AddressResolver {
    fun buildAddress(offset: Long): Address
    fun resolve(name: String): Address?
    fun recordFromStab(name: String, addr: Address): Boolean
}

open class StabOnlyAddressResolver : AddressResolver {
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
            // Conflict: same name at two different addresses across CUs. Keep first; caller logs.
            return false
        }
        return true
    }
}

/**
 * Address-resolution facade. Stab-derived addresses (recorded via
 * `recordFromStab`) win; otherwise we delegate to the label store.
 *
 * Creates `IMPORTED` labels at stab-derived addresses when no symbol exists.
 * Never re-parses the PE/ELF/COFF symbol table directly — Ghidra has already
 * populated the symbol table.
 *
 * **Transactional requirement:** Callers must hold a Program transaction before invoking
 * [recordFromStab], since it may call `labelStore.createLabel()`, which mutates Program state.
 */
class ProgramAddressResolver(private val program: Program) : StabOnlyAddressResolver() {
    /**
     * Record an address learned from a stab record. If `name` is non-blank
     * AND no Ghidra symbol already exists at `addr` carrying that name,
     * create an `IMPORTED` label.
     *
     * Idempotent: subsequent calls with the same (name, addr) are no-ops.
     *
     * **Transactional requirement:** Caller must hold a Program transaction, since
     * [labelStore.createLabel] mutates Program state.
     */
    override fun recordFromStab(name: String, addr: Address): Boolean {
        if (super.recordFromStab(name, addr)) {
            val present = program.symbolTable.getSymbols(addr).any { it.name == name }
            if (!present) {
                program.symbolTable.createLabel(addr, name, SourceType.IMPORTED)
            }
        }
        return true
    }

    override fun buildAddress(offset: Long): Address = program.addressFactory.defaultAddressSpace.getAddress(offset)

    /**
     * Resolve a (possibly mangled) symbol name to an address.
     * Stab-derived map first; falls back to labelStore.getSymbols(name).
     * Returns null if neither source has it.
     */
    override fun resolve(name: String): Address? {
        super.resolve(name)?.let { return it }
        val syms = program.symbolTable.getSymbols(name)
        return syms.firstOrNull()?.address
    }
}
