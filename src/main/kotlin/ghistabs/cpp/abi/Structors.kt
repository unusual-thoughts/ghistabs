package ghistabs.cpp.abi

import ghidra.program.model.listing.Function
import ghistabs.cpp.abi.itanium.ItaniumStructor
import ghistabs.cpp.abi.msvc.MsvcStructor
import ghistabs.cpp.recover.StructorFinder

/**
 * A constructor or destructor as its ABI tells its variants apart: [ItaniumStructor] by the code in its
 * linkage name, [MsvcStructor] by its special name.
 */
interface Structor {
    val isDestructor: Boolean

    /** A destructor that frees the object too, as the vftable slot for its destructor does. */
    val isDeleting: Boolean

    /** How the class [className] spells this member in its own body: `Foo`, `~Foo`. */
    fun displayName(className: String): String
}

/**
 * How an ABI's structors behave, as far as [StructorFinder] and the sizes `operator new` gives
 * ([ghistabs.cpp.recover.NewSizeReader]) need to know.
 */
interface StructorConvention {
    /**
     * Whether a constructor hands back the object it built, which is what tells one from a destructor
     * among the functions that store a vptr. MSVC's do and its destructors return nothing; Itanium's
     * return nothing either, but on ARM, where both return `this`, so neither tells there.
     */
    val constructorsReturnThis: Boolean get() = false

    /** Which of this ABI's variants [func], playing [role], is; null if that takes more. */
    fun structorFor(role: StructorRole, func: Function): Structor? = null

    /**
     * The names a scalar `operator new(size)` goes by: its mangled ones under this ABI ([mangledOperatorNew])
     * and the ones Ghidra's demangler gives it. Not `new[]`, whose size is a count's worth and a cookie.
     */
    val operatorNewNames: Set<String> get() = mangledOperatorNew + DEMANGLED_OPERATOR_NEW

    /** `operator new(size)` as this ABI mangles it, for each pointer size. */
    val mangledOperatorNew: Set<String> get() = emptySet()

    /** The names a scalar `operator delete(void *)` goes by: what a deleting destructor frees `this` with. */
    val operatorDeleteNames: Set<String> get() = mangledOperatorDelete + DEMANGLED_OPERATOR_DELETE

    /** `operator delete(void *)`, and its sized form, as this ABI mangles them. */
    val mangledOperatorDelete: Set<String> get() = emptySet()

    private companion object {
        val DEMANGLED_OPERATOR_NEW = setOf("operator_new", "operator new")
        val DEMANGLED_OPERATOR_DELETE = setOf("operator_delete", "operator delete")
    }
}

/**
 * What [StructorFinder] finds a function that stores a vptr does to its class, whatever the ABI. Which of
 * its [Structor] variants that is takes the ABI's own evidence ([CxxAbi.structorFor]).
 */
enum class StructorRole { CONSTRUCTOR, DESTRUCTOR, DELETING_DESTRUCTOR }
