package ghistabs.cpp.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.address.Address
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Program

/**
 * How an ABI lays out a vtable record and spells its symbols. By default the Itanium and MSVC shape: a
 * header before the address point the vptr holds, then one pointer per slot.
 */
interface VtableLayout {
    /** Bytes of header before the first virtual's entry. */
    fun headerBytes(ptrSize: Int): Long

    /** Whether a typeinfo pointer sits in the header, which is what locates an address point. */
    val hasRttiHeader: Boolean

    /** Where each slot's function pointer sits, in slot order, from a record's [addressPoint] on. */
    fun slots(addressPoint: Address, ptrSize: Int): Sequence<Address> =
        generateSequence(addressPoint) { it.add(ptrSize.toLong()) }

    /** Byte offset of slot [index]'s function pointer from where the record's `_vftable` struct begins. */
    fun slotOffset(index: Int, ptrSize: Int): Long = index.toLong() * ptrSize

    /**
     * Entries the header occupies in a stab's slot numbering (`*<n>`): none where the vptr already
     * points past it, as Itanium's does.
     */
    fun reservedEntries(ptrSize: Int) = 0

    /** Does [symbolName] look like a vtable symbol of this ABI? */
    fun looksLikeVtable(symbolName: String): Boolean

    /**
     * Does [symbolName] name a class's *own* table, rather than a base's secondary? Itanium packs a
     * class's secondaries into the primary record, so every `_ZTV` is one and the default holds;
     * gcc 2.x gives each secondary its own symbol, which only the mangled spelling distinguishes.
     */
    fun isPrimaryVtable(symbolName: String) = looksLikeVtable(symbolName)

    /** Closed-form vtable symbol spellings for [className], most canonical first. */
    fun vtableCandidates(className: String): List<String>

    /** Qualified class name [obj] names, if it is this ABI's demangled vtable object. */
    fun demangledVtableClass(obj: DemangledObject): String?

    /**
     * The reserved entry gcc 2.x puts at the front of a record, as struct fields — the `{vfptr}`
     * points here, so the slots only land on their real byte offsets if the header occupies its own.
     * `cp/class.c:skip_rtti_stuff` reserves two pointer-wide entries with thunks and one 8-byte
     * `{delta, index, pfn}` without; 8 bytes either way on 32-bit. Nothing here is a Pointer, which
     * is what keeps the header out of the slot list everything else counts.
     */
    fun Structure.addReservedHeader() = Unit

    /**
     * The `{delta, index}` half of a gcc 2.x no-thunk entry, which precedes its `pfn` and is what
     * makes the entry 8 bytes wide. `delta` is live at every call site — the dispatch reads it with
     * `movswl` and adds it to `this` before the call — so it is a signed short and worth naming.
     */
    fun Structure.addEntryAdjustment(slot: Int) = Unit

    /**
     * Where the `{vfptr}` holding this record's address point sits in the complete object, as far as
     * the record itself says: Itanium's `offset_to_top`, negated — 0 for a primary, the subobject's
     * offset for a secondary. A gcc 2.x record states no such word; its tables are placed by the
     * symbol that names them and the class struct.
     */
    fun VtableRecord.vfptrOffset(program: Program): Long? = null
}
