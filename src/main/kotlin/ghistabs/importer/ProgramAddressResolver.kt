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
class ProgramAddressResolver(private val program: Program) : StabOnlyAddressResolver() {
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
