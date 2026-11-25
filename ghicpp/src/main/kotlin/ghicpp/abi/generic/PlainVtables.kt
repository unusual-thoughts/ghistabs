package ghicpp.abi.generic

import ghicpp.ClassNaming
import ghicpp.CxxAbi
import ghicpp.VtableRecord
import ghicpp.abi.gcc2.Gcc2Plain
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.mangledBy
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.structorOf
import ghicpp.abi.vtableHeader
import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidrakt.pointerAt

/**
 * Vtables known only as tables of pointers to code, with no RTTI to say whose ABI laid them, such as those
 * [ghicpp.recover.GenericVftableFinder] seeds: the slots start at the label, and the vptr into one sits at the
 * start of the object. The rest is asked of every ABI, which names its runtime alike in a stripped binary.
 */
object PlainVtables : CxxAbi {
    private val abis = listOf(Itanium, Msvc, Gcc2Plain)

    /** How far into its object a base subobject may sit, for the words before a table to read as its offset. */
    const val MAX_SUBOBJECT_OFFSET = 0x10000L

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
    override fun looksLikeVtable(symbolName: String) = false

    override fun vtableCandidates(className: String) = emptyList<String>()

    override fun demangledVtableClass(obj: DemangledObject): String? = null
}

/**
 * Whether an Itanium vtable header comes before [table]: an `offset_to_top` that a subobject could have, then
 * an RTTI word ([isRttiWord]).
 */
fun Program.hasVtableHeader(table: Address): Boolean = vtableHeader(table)?.let {
    it.offsetToTop <= 0 && -it.offsetToTop < PlainVtables.MAX_SUBOBJECT_OFFSET && isRttiPointer(it.rtti)
} == true

/** Whether the word at [at] is an RTTI word ([isRttiPointer]). */
fun Program.isRttiWord(at: Address) = pointerAt(at)?.let(::isRttiPointer) == true

/** Whether [p] may be an RTTI word's value: address 0, with no RTTI, or a pointer to data, a typeinfo. */
fun Program.isRttiPointer(p: Address) =
    p.offset == 0L || memory.getBlock(p)?.let { it.isInitialized && !it.isExecute } == true
