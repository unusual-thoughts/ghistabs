package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledObject
import ghistabs.Demangler
import ghistabs.materialize.itanium.Itanium as ItaniumFacts

/**
 * A C++ ABI's answers about vtables: how a record is laid out, how its symbol is spelled, and which
 * class that symbol names. One implementation per ABI the corpus carries, so a site that needs one
 * of these facts asks the ABI rather than branching on it.
 *
 * Physname composition is deliberately absent: it is asked per *member*, long before any vtable
 * symbol has classified the class, and nothing yet records a producer per compilation unit. It
 * stays on [Gcc2] until something can state which ABI a member belongs to.
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

    /**
     * Whether a `{vfptr}` holds the record *start* rather than the address point, which decides
     * where the `_vftable` struct begins for a virtual call to resolve against its fields.
     */
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
        override fun headerBytes(ptrSize: Int) = ItaniumFacts.vtablePrefixBytes(ptrSize)

        override val hasRttiHeader get() = true
        override val vptrAtRecordStart get() = false

        override fun looksLikeVtable(symbolName: String) = ItaniumFacts.looksLikeZtv(symbolName)
        override fun vtableCandidates(className: String) = ItaniumFacts.ztvCandidates(className)
        override fun demangledVtableClass(obj: DemangledObject) = ItaniumFacts.demangledVtableClass(obj)
    }

    /**
     * gcc 2.95.3's geometry, per `-fvtable-thunks`. `cp/decl.c` makes an entry a bare function
     * pointer with thunks and the record `{short delta; short index; void *pfn;}` without, while
     * `cp/class.c:skip_rtti_stuff` reserves one entry for offset/tdesc and a second, for the tdesc
     * pointer, only with thunks: 8 bytes of header either way on 32-bit.
     *
     * A gcc 2.x `{vfptr}` points at the record start and the call site skips the header itself.
     * `cv_mscom_elf_i386_gcc281` stores `_vt.9CMapBytes` verbatim into the object
     * (`movl $0x807639c,(%ebx)`), and `tinyxml_aout_gcc295.o` dispatches through `add eax,0x8`
     * after loading the vptr.
     */
    sealed interface Gcc2Abi : CxxAbi {
        override fun stride(ptrSize: Int) = ptrSize.toLong()
        override fun pfnOffset(ptrSize: Int) = 0L
        override fun headerBytes(ptrSize: Int) = 2L * ptrSize

        /** gcc 2.x emits no typeinfo pointer, so there is no rtti word to find the address point by. */
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

        /**
         * `delta` and `index` are a `short` each, so together they make exactly one 32-bit word, the
         * only width gcc 2.x ever targeted. (`-fhuge-objects` widens both to `long` and would make
         * this `2 * ptrSize`; no corpus binary uses it.)
         */
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
         * The qualified class a vtable [symbolName] names, whichever ABI spelled it, or null if it
         * is not one. Lets a caller demangle the symbol table once into a class to address index
         * rather than re-scanning it per class.
         *
         * A gcc 2.x name needs the primary screen rather than [looksLikeVtable]: a second marker
         * separates a base, naming that base's secondary table inside the first class, which is a
         * different object from the class's own.
         */
        fun vtableClassOf(symbolName: String): String? = when {
            ItaniumFacts.looksLikeZtv(symbolName) -> ItaniumFacts.vtableClassOf(symbolName)

            Gcc2.looksLikePrimaryVtable(symbolName) ->
                Demangler.of(symbolName)?.let(Gcc2::demangledVtableClass)

            else -> null
        }
    }
}
