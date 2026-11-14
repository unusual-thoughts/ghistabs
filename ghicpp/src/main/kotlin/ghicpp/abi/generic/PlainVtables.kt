package ghicpp.abi.generic

import ghicpp.ClassNaming
import ghicpp.abi.CxxAbi
import ghicpp.abi.VtableRecord
import ghicpp.abi.gcc2.Gcc2Plain
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.msvc.Msvc
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program

/**
 * Vtables known only as tables of pointers to code, with no RTTI to say whose ABI laid them, such as those
 * [ghicpp.recover.GenericVftableFinder] seeds: the slots start at the label, and the vptr into one sits at the
 * start of the object. The rest is asked of every ABI, which names its runtime alike in a stripped binary.
 */
object PlainVtables : CxxAbi {
    private val abis = listOf(Itanium, Msvc, Gcc2Plain)

    override fun recordAt(program: Program, at: Address) = VtableRecord(at, null, this)

    /** 0 for a class's primary; a secondary's own label says its subobject's ([ClassNaming.plainSecondaryLabel]). */
    override fun vfptrOffsetOf(record: VtableRecord, program: Program) = program.symbolTable.getSymbols(record.address)
        .firstNotNullOfOrNull { ClassNaming.plainSubobjectOffset(it.name) } ?: 0L

    override fun isPureVirtualStub(name: String) = abis.any { it.isPureVirtualStub(name) }

    override fun isProbablyMangled(name: String) = CxxAbi.mangledBy(name) != null

    override fun structorOf(mangled: String, className: String?) = CxxAbi.structorOf(mangled)

    override val mangledOperatorNew get() = abis.flatMapTo(mutableSetOf()) { it.mangledOperatorNew }

    override val mangledOperatorDelete get() = abis.flatMapTo(mutableSetOf()) { it.mangledOperatorDelete }

    /** It has no symbols of its own: a table it reads is labelled `vftable` in its class's namespace. */
    override fun looksLikeTableSymbol(symbolName: String) = false

    override fun vtableCandidates(className: String) = emptyList<String>()

    override fun demangledVtableClass(obj: DemangledObject): String? = null
}
