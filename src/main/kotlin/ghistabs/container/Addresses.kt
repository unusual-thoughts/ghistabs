package ghistabs.container

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType

/**
 * Address-resolution facade. Stab-derived addresses (recorded via
 * `recordFromStab`) win; otherwise we delegate to `program.symbolTable`.
 *
 * Creates `IMPORTED` labels at stab-derived addresses when no symbol exists.
 * Never re-parses the PE/ELF/COFF symbol table directly — Ghidra has already
 * populated `program.symbolTable`.
 */
class AddressResolver(
    private val program: Program,
) {
    private val stabMap: MutableMap<String, Address> = mutableMapOf()

    /**
     * Record an address learned from a stab record. If `name` is non-blank
     * AND no Ghidra symbol already exists at `addr` carrying that name,
     * create an `IMPORTED` label.
     *
     * Idempotent: subsequent calls with the same (name, addr) are no-ops.
     */
    fun recordFromStab(
        name: String,
        addr: Address,
    ) {
        if (name.isBlank()) {
            stabMap.putIfAbsent(name, addr)
            return
        }
        val existing = stabMap[name]
        if (existing == null) {
            stabMap[name] = addr
        } else if (existing != addr) {
            // Conflict: same name at two different addresses across CUs. Keep first; caller logs.
            return
        }
        val symtab = program.symbolTable
        val present = symtab.getSymbols(addr).any { it.name == name }
        if (!present) {
            symtab.createLabel(addr, name, SourceType.IMPORTED)
        }
    }

    /**
     * Resolve a (possibly mangled) symbol name to an address.
     * Stab-derived map first; falls back to program.symbolTable.getSymbols(name).
     * Returns null if neither source has it.
     */
    fun resolve(name: String): Address? {
        stabMap[name]?.let { return it }
        val syms = program.symbolTable.getSymbols(name)
        return syms.firstOrNull()?.address
    }
}
