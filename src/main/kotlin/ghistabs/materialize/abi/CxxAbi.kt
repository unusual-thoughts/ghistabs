package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledObject
import ghistabs.Demangler

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

    /** Does [symbolName] look like a vtable symbol of this ABI? */
    fun looksLikeVtable(symbolName: String): Boolean

    /** Closed-form vtable symbol spellings for [className], most canonical first. */
    fun vtableCandidates(className: String): List<String>

    /** Qualified class name [obj] names, if it is this ABI's demangled vtable object. */
    fun demangledVtableClass(obj: DemangledObject): String?

    companion object {
        /** Which ABI a vtable symbol's spelling states. Itanium is the shape of everything else. */
        fun of(symbolName: String): CxxAbi = when {
            Gcc2Thunks.looksLikeVtable(symbolName) -> Gcc2Thunks
            Gcc2Plain.looksLikeVtable(symbolName) -> Gcc2Plain
            else -> Itanium
        }

        /** Every ABI's spelling for [className]'s vtable, Itanium first. */
        fun vtableCandidates(className: String) = Itanium.vtableCandidates(className) +
            Gcc2Plain.vtableCandidates(className) +
            Gcc2Thunks.vtableCandidates(className)

        /**
         * The qualified class a vtable [symbolName] names, whichever ABI spelled it. gcc 2.x needs
         * the primary screen, not [looksLikeVtable]: a second marker separates a base, naming that
         * base's secondary table rather than the class's own.
         */
        fun vtableClassOf(symbolName: String): String? = when {
            Itanium.looksLikeVtable(symbolName) ->
                Demangler.of(symbolName)?.let(Itanium::demangledVtableClass)

            Gcc2.looksLikePrimaryVtable(symbolName) ->
                Demangler.of(symbolName)?.let(Gcc2::demangledVtableClass)

            else -> null
        }
    }
}
