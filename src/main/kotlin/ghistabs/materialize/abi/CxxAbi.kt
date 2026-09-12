package ghistabs.materialize.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.Structure
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolTable

/**
 * How a C++ ABI spells a *member* — the half of [CxxAbi] that never touches a vtable record. Split
 * out because the two are asked at different times: a member's symbol is wanted while reparenting
 * methods, long before any vtable symbol has classified a class.
 */
interface CxxMemberNaming {
    /** A name this ABI mangled, as opposed to a plain C symbol or a compiler label. */
    fun isProbablyMangled(name: String): Boolean

    /**
     * The symbols a member could have been emitted as, most specific first. The stated physname is
     * always tried first and unchanged; an ABI whose stabs put something less than a whole symbol in
     * that field composes the rest from what the stab does state.
     */
    fun physnameCandidates(
        memberName: String,
        className: String,
        isConst: Boolean,
        isVolatile: Boolean,
        stated: String?,
    ): List<String> = listOfNotNull(stated)

    /** How this ABI's stabs spell the implicit assignment operator. */
    val assignmentOperatorName: String

    /** Whether [stated] is *itself* the linkage name of an implicit special member. */
    fun statedIsImplicitMember(stated: String) = false

    /**
     * A member the compiler emits only if it is used: the class's own ctor or dtor, or the implicit
     * assignment operator. gcc declares these for every aggregate a CU sees — plain C structs from
     * system headers, `timeval` and `_IO_FILE` among them — so an absent symbol is the norm rather
     * than a loss, and bucketing them apart is what keeps unresolved-symbol about real problems.
     *
     * Two independent tests, because either half can be the only one available: a member with no
     * physname at all is recognisable by name alone, and one whose physname *is* a whole symbol is
     * recognisable by [statedIsImplicitMember] even when its source name is spelled unusually.
     */
    fun isImplicitMember(memberName: String, className: String, stated: String?): Boolean {
        val leaf = className.substringAfterLast("::")
        return memberName == leaf || memberName == "~$leaf" || memberName == assignmentOperatorName ||
            stated?.let(::statedIsImplicitMember) == true
    }

    /** In-class display form of a ctor/dtor linkage name, or null for anything else. */
    fun specialMemberDisplayName(mangled: String, className: String): String?

    /**
     * A member whose definition the compiler may legitimately have dropped, so a missing Function at
     * its asserted address is expected rather than a failure worth warning about.
     */
    fun isInlineStdMember(name: String) = false
}

/**
 * A C++ ABI's answers about vtables — record geometry, symbol spelling, and which class a symbol
 * names — on top of [CxxMemberNaming]'s answers about members. Sealed, because [ofVtableSymbol]
 * enumerates the spellings: a symbol either matches one of these ABIs or names no vtable at all.
 */
sealed interface CxxAbi : CxxMemberNaming {
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
        fun ofVtableSymbol(symbolName: String): CxxAbi? = when {
            Gcc2Thunks.looksLikeVtable(symbolName) -> Gcc2Thunks
            Gcc2Plain.looksLikeVtable(symbolName) -> Gcc2Plain
            Itanium.looksLikeVtable(symbolName) -> Itanium
            else -> null
        }

        /** Every ABI's spelling for [className]'s vtable, Itanium first. */
        fun vtableCandidates(className: String) = Itanium.vtableCandidates(className) +
            Gcc2Plain.vtableCandidates(className) +
            Gcc2Thunks.vtableCandidates(className)

        /**
         * The ABI a whole binary was built with, for every question no individual symbol settles —
         * how a physname is spelled, how an implicit member is recognised, what a mangled name looks
         * like. One producer per binary, so any one symbol that could only have come from a given
         * ABI states it for all of them.
         *
         * A vtable spelling is the decisive evidence and is taken wherever it appears, including
         * from an *undefined* symbol: `tinyxml_aout_gcc295.o` names `__vt_13TiXmlDocument` without
         * defining it, which states the ABI as well as a definition would. Failing that the mangled
         * member names vote — a C++ binary with no polymorphic class anywhere has no vtable to read,
         * but it still has members, and counting them means no lone false positive can carry the
         * whole binary. Null when nothing votes at all: a C binary, or a C++ one from a compiler
         * whose mangling is neither of these (the WordPerfect corpus has SunPro, XLC and DEC ones).
         */
        fun prevailing(symbolNames: Sequence<String>): CxxAbi? {
            val byMember = mutableMapOf<CxxAbi, Int>()
            for (name in symbolNames) {
                ofVtableSymbol(name)?.takeIf { it.isPrimaryVtable(name) }?.let { return it }
                mangledBy(name)?.let { byMember[it] = byMember.getOrDefault(it, 0) + 1 }
            }
            return byMember.maxByOrNull { it.value }?.key
        }

        /** [prevailing] over a program's symbols. Typed, because SymbolIterator is both an Iterator
         *  and an Iterable, and `asSequence` is on both. */
        fun SymbolTable.prevailingAbi(): CxxAbi? {
            val symbols: Iterator<Symbol> = symbolIterator
            return prevailing(symbols.asSequence().map { it.name })
        }

        /**
         * Which ABI mangled [name], as a member. Nothing here tells the two gcc 2.x ABIs apart —
         * they mangle members identically and differ only in vtable geometry, which a binary with no
         * vtable symbol has no record of — so [Gcc2Thunks] stands for gcc 2.x.
         */
        private fun mangledBy(name: String): CxxAbi? = when {
            Itanium.isProbablyMangled(name) -> Itanium
            Gcc2.isProbablyMangled(name) -> Gcc2Thunks
            else -> null
        }
    }
}
