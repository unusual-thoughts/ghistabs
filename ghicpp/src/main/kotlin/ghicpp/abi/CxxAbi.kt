package ghicpp.abi

import ghicpp.BaseDecl
import ghicpp.ClassPassInput
import ghicpp.MemberDecl
import ghicpp.abi.gcc2.Gcc2
import ghicpp.abi.gcc2.Gcc2Plain
import ghicpp.abi.gcc2.Gcc2Thunks
import ghicpp.abi.generic.PlainVtables
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.itanium.SpecialName
import ghicpp.abi.msvc.Msvc
import ghicpp.templateLeaf
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor

/** How a C++ ABI spells a member's symbol, which is asked before any vtable has said which ABI it is. */
interface CxxMemberNaming {
    /** Whether this ABI mangled [name], as opposed to a C symbol or a compiler label. */
    fun isProbablyMangled(name: String): Boolean

    /** The symbols [m] may have been emitted as, the stated physname first. */
    fun physnameCandidates(m: MemberDecl, className: String): List<String> = listOfNotNull(m.mangled)

    /** How this ABI's stabs spell the implicit assignment operator. */
    val assignmentOperatorName: String get() = "operator="

    /** Whether [physname] is itself the symbol of an implicit special member. */
    fun physnameIsImplicit(physname: String) = false

    /**
     * A constructor, destructor or assignment operator the compiler emits only when used. gcc declares
     * them for every aggregate, C structs included, so a missing symbol is expected. Told by name, or by a
     * physname that is itself such a symbol ([physnameIsImplicit]).
     */
    fun isImplicitMember(m: MemberDecl, className: String): Boolean {
        val leaf = className.templateLeaf
        return m.name == leaf || m.name == "~$leaf" || m.name == assignmentOperatorName ||
            m.mangled?.let(::physnameIsImplicit) == true
    }

    /** The constructor or destructor [mangled] names, given [className] where the mangling needs it; else null. */
    fun structorOf(mangled: String, className: String? = null): Structor?

    /** A member the compiler may have inlined away, so a missing function is no failure. */
    fun isInlineStdMember(name: String) = false
}

/**
 * A C++ ABI: how it names members ([CxxMemberNaming]), lays out vtables ([VtableLayout]) and spells
 * them ([VtableSymbols]), and builds and destroys objects ([StructorConvention]).
 */
interface CxxAbi :
    CxxMemberNaming,
    VtableLayout,
    VtableSymbols,
    StructorConvention {
    /**
     * [cls]'s direct bases from this ABI's own records: Itanium's typeinfo, MSVC's Base Class Array. Null
     * where there are none to read, as under gcc 2.x, which builds its typeinfo at run time.
     */
    fun basesOf(program: Program, cls: Namespace): List<BaseDecl>? = null

    /** The record that says where an object's virtual bases sit: Itanium's vtable, MSVC's vbtable. */
    val virtualBaseRecord: String get() = "vtable"

    /**
     * Whether the table whose address point is [vftable] is one of this ABI's records, by the record's symbols.
     * By default a record starts at its address point, so its vtable symbol is there, as gcc 2.x's is.
     */
    fun ownsVftable(program: Program, vftable: Address): Boolean =
        program.symbolTable.getSymbols(vftable).any { looksLikeTableSymbol(it.name) }

    companion object {
        /** The ABI whose vtable symbol [symbolName] is, a gcc 2.x secondary's included; null if none. */
        fun ofVtableSymbol(symbolName: String): CxxAbi? = when {
            Gcc2Thunks.looksLikeTableSymbol(symbolName) -> Gcc2Thunks
            Gcc2Plain.looksLikeTableSymbol(symbolName) -> Gcc2Plain
            Itanium.looksLikeTableSymbol(symbolName) -> Itanium
            Msvc.looksLikeTableSymbol(symbolName) -> Msvc
            else -> null
        }

        /**
         * The ABI whose record the table at the address point [vftable] is ([ownsVftable]); [PlainVtables] for a
         * table no record names, such as one seeded off a pointer table.
         */
        fun ofVftable(program: Program, vftable: Address): CxxAbi =
            listOf(Gcc2Thunks, Gcc2Plain, Msvc, Itanium).firstOrNull { it.ownsVftable(program, vftable) }
                ?: PlainVtables

        /** Data the compiler generated for a class, a vtable or typeinfo, rather than any the source declares. */
        fun isGeneratedData(name: String) =
            Itanium.isGeneratedData(name) || ofVtableSymbol(name) != null || Gcc2.isTypeinfoName(name)

        /** A `this`-adjusting thunk, by its gcc 2.x or Itanium symbol. */
        fun looksLikeThunk(name: String) = Gcc2.looksLikeThunk(name) || Itanium.specialName(name) == SpecialName.THUNK

        /** Every gcc ABI's symbols for [className]'s vtable, Itanium first. */
        fun vtableCandidates(className: String) = buildList {
            addAll(Itanium.vtableCandidates(className))
            addAll(Gcc2Plain.vtableCandidates(className))
            addAll(Gcc2Thunks.vtableCandidates(className))
        }

        /**
         * The ABI a binary was built with: that of the first primary vtable symbol, even an undefined one,
         * else the one most mangled names are in. Null for a binary with neither, such as a C one.
         */
        fun prevailing(symbolNames: Sequence<String>): CxxAbi? {
            val byMember = mutableMapOf<CxxAbi, Int>()
            for (name in symbolNames) {
                ofVtableSymbol(name)?.takeIf { it.isPrimaryVtable(name) }?.let { return it }
                mangledBy(name)?.let { byMember[it] = byMember.getOrDefault(it, 0) + 1 }
            }
            return byMember.maxByOrNull { it.value }?.key
        }

        /** [prevailing] over a program's symbols. */
        fun SymbolTable.prevailingAbi(): CxxAbi? {
            // A SymbolIterator is an Iterator and an Iterable, and `asSequence` is on both.
            val symbols: Iterator<Symbol> = symbolIterator
            return prevailing(symbols.asSequence().map { it.name })
        }

        /** The constructor or destructor [mangled] names, under whichever ABI mangled it. */
        fun structorOf(mangled: String): Structor? =
            listOf(Msvc, Gcc2Thunks, Itanium).firstNotNullOfOrNull { it.structorOf(mangled) }

        /** The ABI that mangled [name]; [Gcc2Thunks] for gcc 2.x, whose two ABIs mangle alike. */
        fun mangledBy(name: String): CxxAbi? = when {
            Itanium.isProbablyMangled(name) -> Itanium
            Gcc2.isProbablyMangled(name) -> Gcc2Thunks
            Msvc.isProbablyMangled(name) -> Msvc
            else -> null
        }
    }
}

/** A constructor or destructor variant, as its ABI names them: `ItaniumStructor`, `MsvcStructor`, `Gcc2Structor`. */
interface Structor {
    val isDestructor: Boolean

    /** Whether this destructor frees the object too, as the one a vftable slot holds does. */
    val isDeleting: Boolean

    /** How the class [className] spells this member in its own body: `Foo`, `~Foo`. */
    fun displayName(className: String): String
}

/** How an ABI's constructors and destructors behave, for `ThisFunctionDissector` and `AllocationSizeFinder`. */
interface StructorConvention {
    /** The variant [func] is, given its [role]; null where that doesn't say. */
    fun structorFor(role: StructorRole, func: Function): Structor? = null

    /** The names of a scalar `operator new(size)`, mangled and demangled. Not `new[]`'s, which adds a cookie. */
    val operatorNewNames: Set<String> get() = mangledOperatorNew + DEMANGLED_OPERATOR_NEW

    /** `operator new(size)` as this ABI mangles it, for each `size_t`. */
    val mangledOperatorNew: Set<String> get() = emptySet()

    /** The names of a scalar `operator delete`, which a deleting destructor frees `this` with. */
    val operatorDeleteNames: Set<String> get() = mangledOperatorDelete + DEMANGLED_OPERATOR_DELETE

    /** `operator delete(void *)`, and its sized form, as this ABI mangles them. */
    val mangledOperatorDelete: Set<String> get() = emptySet()

    private companion object {
        val DEMANGLED_OPERATOR_NEW = setOf("operator_new", "operator new")
        val DEMANGLED_OPERATOR_DELETE = setOf("operator_delete", "operator delete")
    }
}

/** What a function storing vptrs does to its class, in any ABI; [StructorConvention.structorFor] gives the variant. */
enum class StructorRole { CONSTRUCTOR, DESTRUCTOR, DELETING_DESTRUCTOR }

/**
 * Reads an ABI's RTTI, from the labels, memory and structs other analyzers laid, and interprets it into the
 * classes the class pass recovers.
 */
interface RttiParser {
    /** The ABI whose RTTI this reads. */
    val abi: CxxAbi

    /** The classes the RTTI describes. */
    fun parse(monitor: TaskMonitor = TaskMonitor.DUMMY): ClassPassInput
}
