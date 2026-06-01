package ghistabs.container

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolTable

/**
 * Minimal interface for label storage operations. Decouples AddressResolver from the
 * full SymbolTable interface, making testing easier.
 */
interface LabelStore {
    /**
     * Get all symbols at a given address.
     */
    fun getSymbols(addr: Address): List<Symbol>

    /**
     * Get all symbols with a given name.
     */
    fun getSymbols(name: String): List<Symbol>

    /**
     * Create a label at the given address with the given name and source type.
     */
    fun createLabel(addr: Address, name: String, source: SourceType): Symbol
}

/**
 * Adapter to expose SymbolTable as a LabelStore.
 */
internal class SymbolTableAdapter(private val symbolTable: SymbolTable) : LabelStore {
    override fun getSymbols(addr: Address) = symbolTable.getSymbols(addr).toList()

    override fun getSymbols(name: String) = symbolTable.getSymbols(name).toList()

    override fun createLabel(addr: Address, name: String, source: SourceType): Symbol =
        symbolTable.createLabel(addr, name, source)
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
class AddressResolver(private val labelStore: LabelStore) {
    private val stabMap: MutableMap<String, Address> = mutableMapOf()

    /**
     * Convenience constructor that wraps a SymbolTable from a Program.
     */
    constructor(program: Program) : this(SymbolTableAdapter(program.symbolTable))

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
    fun recordFromStab(name: String, addr: Address) {
        if (name.isBlank()) {
            return
        }
        val existing = stabMap[name]
        if (existing == null) {
            stabMap[name] = addr
        } else if (existing != addr) {
            // Conflict: same name at two different addresses across CUs. Keep first; caller logs.
            return
        }
        val present = labelStore.getSymbols(addr).any { it.name == name }
        if (!present) {
            labelStore.createLabel(addr, name, SourceType.IMPORTED)
        }
    }

    /**
     * Resolve a (possibly mangled) symbol name to an address.
     * Stab-derived map first; falls back to labelStore.getSymbols(name).
     * Returns null if neither source has it.
     */
    fun resolve(name: String): Address? {
        stabMap[name]?.let { return it }
        val syms = labelStore.getSymbols(name)
        return syms.firstOrNull()?.address
    }
}
