package ghistabs.cpp.abi

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.pointerInto
import ghistabs.cpp.thisStorage
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

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
 * ([ghistabs.cpp.NewSizeReader]) need to know.
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

/**
 * What a function does to its `this`: the [classes], by type descriptor, whose vftables it stores where
 * they belong in it, and whether it hands `this` back ([returnsThis]).
 */
data class VptrStores(val classes: Set<Address>, val returnsThis: Boolean)

/**
 * The class a function storing [classes]' vftables builds or tears down: the most derived of them,
 * which the others are bases of, inlined. Null for classes that are not one line of descent.
 */
fun storedClass(classes: Set<Address>, ancestors: (Address) -> Set<Address>): Address? =
    classes.singleOrNull { c -> classes.all { it == c || it in ancestors(c) } }

/**
 * Finds constructors and destructors off the decompiler, by the vtables of [tables] they store through
 * `this`: each table's address point, its class, and how far into the object its vptr sits (the
 * subobject's offset, plus the vptr's within it, which only gcc 2.x puts anywhere but 0).
 */
class StructorFinder(
    private val program: Program,
    private val tables: Map<Address, Pair<Address, Long>>,
    sink: DiagnosticSink,
) : DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    /** Each structor's class and role, given the vftable [slots] and the classes whose tables hold them. */
    fun find(
        slots: Map<Function, Set<Address>>,
        ancestors: (Address) -> Set<Address>,
        convention: StructorConvention,
        monitor: TaskMonitor,
    ) = read(slots.keys, monitor).roles(slots, ancestors, convention)

    /** What the functions do to `this`: the vptrs each storer stores ([stores]), and what each calls on it. */
    class Reading(val stores: Map<Function, VptrStores>, val thisCalls: Map<Function, Set<Function>>) {
        /**
         * A constructor is never virtual, so a slot that runs a storer on `this` destroys it: a deleting
         * destructor if it then frees it, and the storer it calls the destructor; the store may be a base's,
         * a destructor with nothing to do before its base's having none of its own. Where constructors
         * return `this`, that tells the other storers apart.
         */
        fun roles(
            slots: Map<Function, Set<Address>>,
            ancestors: (Address) -> Set<Address>,
            convention: StructorConvention,
        ): Map<Function, Pair<Address, StructorRole>> = buildMap {
            val returnsThis = convention.constructorsReturnThis
            val owners = stores.mapNotNull { (f, s) -> storedClass(s.classes, ancestors)?.let { f to it } }.toMap()
            fun mayDestroy(f: Function) = !returnsThis || stores[f]?.returnsThis != true

            // The holder a slot deletes, if it tears down a [cls]: [cls], or the one class below it the others are.
            fun deleting(held: Set<Address>, cls: Address): Address? {
                val derived = held.filter { it == cls || cls in ancestors(it) }
                return derived.singleOrNull { c -> derived.all { it == c || c in ancestors(it) } }
            }
            for ((slot, held) in slots) {
                val own = owners[slot]
                when {
                    // Itanium's vtable holds the complete object destructor too, which frees nothing.
                    !frees(slot, convention) -> own?.let { this[slot] = it to StructorRole.DESTRUCTOR }

                    own != null -> deleting(held, own)?.let { this[slot] = it to StructorRole.DELETING_DESTRUCTOR }

                    else -> thisCalls[slot].orEmpty().filter(::mayDestroy)
                        .mapNotNull { f -> owners[f]?.let { cls -> deleting(held, cls)?.let { Triple(f, cls, it) } } }
                        .singleOrNull()?.let { (dtor, cls, holder) ->
                            this[slot] = holder to StructorRole.DELETING_DESTRUCTOR
                            putIfAbsent(dtor, cls to StructorRole.DESTRUCTOR)
                        }
                }
            }
            if (returnsThis) {
                for ((f, cls) in owners) {
                    putIfAbsent(f, cls to if (mayDestroy(f)) StructorRole.DESTRUCTOR else StructorRole.CONSTRUCTOR)
                }
            }
        }

        private fun frees(f: Function, convention: StructorConvention) =
            thisCalls[f].orEmpty().any { it.name in convention.operatorDeleteNames }
    }

    /**
     * The stores of each function writing one of [tables], and what those and [others] call on `this`. A
     * store counts only through `this` at the table's own offset, which leaves out locals built inline and
     * member objects; a call, only with `this` first, which leaves out a local built and destroyed.
     */
    private fun read(others: Collection<Function>, monitor: TaskMonitor): Reading {
        val writes = buildMap {
            for ((table, served) in tables) {
                for (ref in program.referenceManager.getReferencesTo(table)) {
                    val at = ref.fromAddress
                    if (program.listing.getInstructionAt(at) == null) continue
                    val func = program.functionManager.getFunctionContaining(at) ?: continue
                    getOrPut(func) { mutableMapOf() }.getOrPut(at) { mutableListOf() } += served
                }
            }
        }
        if (writes.isEmpty() || thisStorage == null) return Reading(emptyMap(), emptyMap())
        val stores = mutableMapOf<Function, VptrStores>()
        val thisCalls = mutableMapOf<Function, Set<Function>>()
        DecompInterface().useWith(program) { decomp ->
            for (func in writes.keys + others) {
                if (monitor.isCancelled) break
                val high = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
                if (high == null) {
                    debug("structor-undecompiled", func.name, func.entryPoint)
                    continue
                }
                writes[func]?.let { stores[func] = high.vptrStores(it) }
                thisCalls[func] = high.thisCalls()
            }
        }
        return Reading(stores, thisCalls)
    }

    private fun HighFunction.thisCalls() = pcodeOps.asSequence()
        .filter { it.opcode == PcodeOp.CALL && it.numInputs > 1 && it.getInput(1).thisOffset() == 0L }
        .mapNotNull { program.functionManager.getFunctionAt(it.getInput(0).address) }
        .mapTo(mutableSetOf()) { it.getThunkedFunction(true) ?: it }

    private fun HighFunction.vptrStores(at: Map<Address, List<Pair<Address, Long>>>): VptrStores {
        val classes = mutableSetOf<Address>()
        var returnsThis = false
        for (op in pcodeOps.asSequence()) {
            when (op.opcode) {
                PcodeOp.STORE -> {
                    val served = at[op.seqnum.target] ?: continue
                    val offset = op.getInput(1).thisOffset() ?: continue
                    served.filter { it.second == offset }.mapTo(classes) { it.first }
                }

                PcodeOp.RETURN -> if (op.numInputs > 1 && op.getInput(1).thisOffset() == 0L) returnsThis = true
            }
        }
        return VptrStores(classes, returnsThis)
    }

    /** How far past `this` [this] points; null if it points into something else. */
    private fun Varnode.thisOffset() = pointerInto().takeIf { it.isThis(thisStorage) }?.offset

    private companion object {
        const val DECOMPILE_TIMEOUT_SECONDS = 30
    }
}
