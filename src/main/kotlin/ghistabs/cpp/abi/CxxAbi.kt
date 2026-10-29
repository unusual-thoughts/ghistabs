package ghistabs.cpp.abi

import ghidra.app.util.demangler.DemangledObject
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolTable
import ghistabs.cpp.BaseDecl
import ghistabs.cpp.MemberDecl
import ghistabs.cpp.templateLeaf

/**
 * How a C++ ABI spells a *member* — the half of [CxxAbi] that never touches a vtable record. Split
 * out because the two are asked at different times: a member's symbol is wanted while reparenting
 * methods, long before any vtable symbol has classified a class.
 */
interface CxxMemberNaming {
    /** A name this ABI mangled, as opposed to a plain C symbol or a compiler label. */
    fun isProbablyMangled(name: String): Boolean

    /**
     * The symbols [m] could have been emitted as, most specific first. The stated physname is always
     * tried first and unchanged; an ABI whose stabs put something less than a whole symbol in that
     * field composes the rest from what the stab does state.
     */
    fun physnameCandidates(m: MemberDecl, className: String): List<String> = listOfNotNull(m.mangled)

    /** How this ABI's stabs spell the implicit assignment operator. */
    val assignmentOperatorName: String

    /** Whether a physname is *itself* the linkage name of an implicit special member. */
    fun physnameIsImplicit(physname: String) = false

    /**
     * A member the compiler emits only if it is used: the class's own ctor or dtor, or the implicit
     * assignment operator. gcc declares these for every aggregate a CU sees — plain C structs from
     * system headers, `timeval` and `_IO_FILE` among them — so an absent symbol is the norm rather
     * than a loss, and bucketing them apart is what keeps unresolved-symbol about real problems.
     *
     * Two independent tests, because either half can be the only one available: a member with no
     * physname at all is recognisable by name alone, and one whose physname *is* a whole symbol is
     * recognisable by [physnameIsImplicit] even when its source name is spelled unusually.
     */
    fun isImplicitMember(m: MemberDecl, className: String): Boolean {
        val leaf = className.templateLeaf
        return m.name == leaf || m.name == "~$leaf" || m.name == assignmentOperatorName ||
            m.mangled?.let(::physnameIsImplicit) == true
    }

    /**
     * Which constructor or destructor a linkage name mangles, of [className] where the ABI's mangling
     * needs the class to tell; null for anything else.
     */
    fun structorOf(mangled: String, className: String? = null): Structor?

    /**
     * A member whose definition the compiler may legitimately have dropped, so a missing Function at
     * its asserted address is expected rather than a failure worth warning about.
     */
    fun isInlineStdMember(name: String) = false
}

/**
 * A C++ ABI: how it names members ([CxxMemberNaming]), lays out vtables ([VtableLayout]), and builds and
 * destroys objects. Sealed, because [ofVtableSymbol] enumerates the spellings: a symbol either matches
 * one of these ABIs or names no vtable at all.
 */
sealed interface CxxAbi :
    CxxMemberNaming,
    VtableLayout {
    /**
     * Whether a constructor hands back the object it built, which is what tells one from a destructor
     * among the functions that store a vptr ([StructorFinder]). MSVC's do and its destructors return nothing;
     * Itanium's return nothing either, but on ARM, where both return `this`, so neither tells there.
     */
    val constructorsReturnThis: Boolean get() = false

    /**
     * [cls]'s direct bases, as this ABI's own records in [program] say, without the stabs: Itanium's
     * typeinfo and MSVC's Base Class Array. Null where there is nothing to read, as under gcc 2.x, whose
     * typeinfo is filled in at run time, rather than a class with no bases.
     */
    fun basesOf(program: Program, cls: Namespace): List<BaseDecl>? = null

    /** Which of this ABI's variants [func], playing [role] ([StructorFinder]), is; null if that takes more. */
    fun structorFor(role: StructorRole, func: Function): Structor? = null

    /**
     * The names a scalar `operator new(size)` goes by: its mangled ones under this ABI ([mangledOperatorNew])
     * and the ones Ghidra's demangler gives it. Not `new[]`, whose size is a count's worth and a cookie.
     */
    val operatorNewNames: Set<String> get() = mangledOperatorNew + DEMANGLED_OPERATOR_NEW

    /** `operator new(size)` as this ABI mangles it, for each pointer size. */
    val mangledOperatorNew: Set<String> get() = emptySet()

    companion object {
        private val DEMANGLED_OPERATOR_NEW = setOf("operator_new", "operator new")

        /**
         * Which ABI a vtable symbol's spelling states, or null if it spells no vtable at all. A
         * gcc 2.x *secondary* table answers here too — it is still that ABI's geometry; screening
         * it out is the job of whoever wants a class's own table.
         */
        fun ofVtableSymbol(symbolName: String): CxxAbi? = when {
            Gcc2Thunks.looksLikeVtable(symbolName) -> Gcc2Thunks
            Gcc2Plain.looksLikeVtable(symbolName) -> Gcc2Plain
            Itanium.looksLikeVtable(symbolName) -> Itanium
            Msvc.looksLikeVtable(symbolName) -> Msvc
            else -> null
        }

        /**
         * Data the compiler generated for a class, in either ABI's spelling: Itanium's vtables and
         * typeinfo ([Itanium.isGeneratedData]), gcc 2.x's vtables and typeinfo objects. None of it is
         * written in the source.
         */
        fun isGeneratedData(name: String) =
            Itanium.isGeneratedData(name) || ofVtableSymbol(name) != null || Gcc2.isTypeinfoName(name)

        /** A this-adjusting thunk by its linkage name: gcc 2.x [Gcc2.looksLikeThunk] or Itanium [SpecialName.THUNK]. */
        fun looksLikeThunk(name: String) = Gcc2.looksLikeThunk(name) || Itanium.specialName(name) == SpecialName.THUNK

        /** Every ABI's spelling for [className]'s vtable, Itanium first. */
        fun vtableCandidates(className: String) = buildList {
            addAll(Itanium.vtableCandidates(className))
            addAll(Gcc2Plain.vtableCandidates(className))
            addAll(Gcc2Thunks.vtableCandidates(className))
        }

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
         * whose mangling is neither of these.
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

        /** Which constructor or destructor [mangled] is under whichever ABI mangled it. */
        fun structorOf(mangled: String): Structor? =
            listOf(Msvc, Gcc2Thunks, Itanium).firstNotNullOfOrNull { it.structorOf(mangled) }

        /**
         * Which ABI mangled [name], as a member. Nothing here tells the two gcc 2.x ABIs apart —
         * they mangle members identically and differ only in vtable geometry, which a binary with no
         * vtable symbol has no record of — so [Gcc2Thunks] stands for gcc 2.x.
         */

        fun mangledBy(name: String): CxxAbi? = when {
            Itanium.isProbablyMangled(name) -> Itanium
            Gcc2.isProbablyMangled(name) -> Gcc2Thunks
            Msvc.isProbablyMangled(name) -> Msvc
            else -> null
        }
    }
}
