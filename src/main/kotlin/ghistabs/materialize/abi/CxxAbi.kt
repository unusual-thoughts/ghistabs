package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledObject
import ghistabs.Demangler
import ghistabs.materialize.itanium.Itanium as ItaniumFacts

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

    data object Itanium : CxxAbi {
        override fun stride(ptrSize: Int) = ptrSize.toLong()
        override fun pfnOffset(ptrSize: Int) = 0L

        /** `offset_to_top` then the typeinfo pointer (ABI §2.5.2). */
        override fun headerBytes(ptrSize: Int) = 2L * ptrSize

        override val hasRttiHeader get() = true
        override val vptrAtRecordStart get() = false

        override fun looksLikeVtable(symbolName: String) = with(ItaniumFacts) {
            symbolName.trimDoubleUnderscore().startsWith(ItaniumFacts.VTABLE_PREFIX)
        }

        /** Templates have no closed form; [vtableClassOf] finds those. */
        override fun vtableCandidates(className: String) = ItaniumFacts.mangleClassName(className).let {
            listOf(
                "${ItaniumFacts.VTABLE_PREFIX}$it",
                "_${ItaniumFacts.VTABLE_PREFIX}$it", // Cygwin/PE leading underscore
                "$className::${ItaniumFacts.DEMANGLED_VTABLE}",
            )
        }

        override fun demangledVtableClass(obj: DemangledObject) =
            ItaniumFacts.addressTableClass(obj, ItaniumFacts.DEMANGLED_VTABLE)
    }

    /**
     * gcc 2.95.3, `cp/class.c:skip_rtti_stuff`: two pointer header entries with thunks, one 8-byte
     * record without, so 8 bytes either way on 32-bit. The vptr holds the record start and the call
     * site skips the header (`tinyxml_aout_gcc295.o` dispatches through `add eax,0x8`).
     */
    sealed interface Gcc2Abi : CxxAbi {
        override fun stride(ptrSize: Int) = ptrSize.toLong()
        override fun pfnOffset(ptrSize: Int) = 0L
        override fun headerBytes(ptrSize: Int) = 2L * ptrSize

        /** gcc 2.x emits no typeinfo pointer, so no rtti word locates the address point. */
        override val hasRttiHeader get() = false
        override val vptrAtRecordStart get() = true

        override fun demangledVtableClass(obj: DemangledObject) = Gcc2.demangledVtableClass(obj)
    }

    /** `__vt_`: the `this` adjustment moved into a thunk, so an entry is the pfn. */
    data object Gcc2Thunks : Gcc2Abi {
        override fun looksLikeVtable(symbolName: String) = Gcc2.looksLikeThunkVtable(symbolName)

        override fun vtableCandidates(className: String) =
            listOf("${Gcc2.THUNK_VTABLE_PREFIX}${Gcc2.mangleClassName(className)}")
    }

    /** `_vt.`/`_vt$`: `{delta, index, pfn}` entries, twice as wide, with pfn in the second word. */
    data object Gcc2Plain : Gcc2Abi {
        override fun stride(ptrSize: Int) = 2L * ptrSize

        /** `delta` and `index` are a `short` each: one 32-bit word. (`-fhuge-objects` would widen
         *  both to `long`; no corpus binary uses it.) */
        override fun pfnOffset(ptrSize: Int) = ptrSize.toLong()

        override fun looksLikeVtable(symbolName: String) =
            Gcc2.looksLikeVtable(symbolName) && !Gcc2.looksLikeThunkVtable(symbolName)

        override fun vtableCandidates(className: String) = Gcc2.mangleClassName(className)
            .let { m -> Gcc2.CPLUS_MARKERS.map { "${Gcc2.VTABLE_PREFIX}$it$m" } }
    }

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
