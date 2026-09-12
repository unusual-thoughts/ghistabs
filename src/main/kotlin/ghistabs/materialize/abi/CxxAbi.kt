package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.Structure

/**
 * A C++ ABI's answers about vtables: record geometry, symbol spelling, and which class a symbol
 * names. Physname composition stays on [Gcc2]: it is asked per member, before any vtable symbol has
 * classified the class, and nothing records a producer per compilation unit.
 */
sealed interface CxxAbi {
    /** Bytes between consecutive entries. */
    fun stride(ptrSize: Int): Long

    /** Where `pfn` sits inside an entry. */
    fun pfnOffset(ptrSize: Int): Long

    /** Bytes of reserved header before the first virtual's entry. */
    fun headerBytes(ptrSize: Int): Long

    /** Whether a typeinfo pointer sits in the header, which is what locates an address point. */
    val hasRttiHeader: Boolean

    /** Whether a `{vfptr}` holds the record *start*, which is where the `_vftable` struct begins. */
    val vptrAtRecordStart: Boolean

    /** Byte offset of slot [index]'s `pfn` from wherever the struct begins. */
    fun slotOffset(index: Int, ptrSize: Int): Long =
        (if (vptrAtRecordStart) headerBytes(ptrSize) else 0L) + index * stride(ptrSize) + pfnOffset(ptrSize)

    /**
     * Entries the header occupies, which is the bias a stab's `*<n>` carries: `DECL_VINDEX` counts
     * from wherever the `{vfptr}` points, and [vptrAtRecordStart] is that difference. Measured both
     * ways — `_ZTVSt9type_info`'s stabs declare 0/1/5 for a record whose vptr is already past the
     * header, while every gcc 2.x first virtual starts at the entry after the reserved ones
     * (`cv_mscom_elf_i386_gcc281`'s dtors are `*1` with one 8-byte entry reserved,
     * `tinyxml_aout_gcc295.o`'s are `*2` with two pointer-wide ones).
     */
    fun reservedEntries(ptrSize: Int) = if (vptrAtRecordStart) (headerBytes(ptrSize) / stride(ptrSize)).toInt() else 0

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

    companion object {
        /**
         * Which ABI a vtable symbol's spelling states, or null if it spells no vtable at all. A
         * gcc 2.x *secondary* table answers here too — it is still that ABI's geometry; screening
         * it out is the job of whoever wants a class's own table.
         */
        fun of(symbolName: String): CxxAbi? = when {
            Gcc2Thunks.looksLikeVtable(symbolName) -> Gcc2Thunks
            Gcc2Plain.looksLikeVtable(symbolName) -> Gcc2Plain
            Itanium.looksLikeVtable(symbolName) -> Itanium
            else -> null
        }

        /** Every ABI's spelling for [className]'s vtable, Itanium first. */
        fun vtableCandidates(className: String) = Itanium.vtableCandidates(className) +
            Gcc2Plain.vtableCandidates(className) +
            Gcc2Thunks.vtableCandidates(className)
    }
}
