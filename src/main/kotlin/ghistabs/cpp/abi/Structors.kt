package ghistabs.cpp.abi

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.abi.itanium.Itanium
import ghistabs.cpp.abi.itanium.ItaniumStructor
import ghistabs.cpp.abi.msvc.MsvcStructor
import ghistabs.cpp.recover.StructorFinder
import ghistabs.cpp.recover.pointerInto
import ghistabs.cpp.recover.thisStorage
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/** A constructor or destructor variant, as its ABI names them: `ItaniumStructor`, `MsvcStructor`, `Gcc2Structor`. */
interface Structor {
    val isDestructor: Boolean

    /** Whether this destructor frees the object too, as the one a vftable slot holds does. */
    val isDeleting: Boolean

    /** How the class [className] spells this member in its own body: `Foo`, `~Foo`. */
    fun displayName(className: String): String
}

/** How an ABI's constructors and destructors behave, for `StructorFinder` and `NewSizeReader`. */
interface StructorConvention {
    /** Whether constructors return `this` and destructors don't, as under MSVC, which tells the two apart. */
    val constructorsReturnThis: Boolean get() = false

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
