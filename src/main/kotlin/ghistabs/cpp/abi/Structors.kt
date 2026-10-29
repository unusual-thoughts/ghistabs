package ghistabs.cpp.abi

import ghidra.app.decompiler.DecompInterface
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.util.task.TaskMonitor
import ghistabs.Demangler
import ghistabs.cpp.pointerInto
import ghistabs.cpp.thisStorage
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/**
 * A constructor's or destructor's variant: Itanium's, by the code in its linkage name ([of]), or MSVC's,
 * whose deleting destructors ([SCALAR_DELETING_DTOR], [VECTOR_DELETING_DTOR]) are functions of their
 * own. gcc >= 3 emits one function per variant it needs, all under the one name the source gives.
 */
enum class StructorVariant(val code: String, val label: String, val isDestructor: Boolean) {
    COMPLETE_CTOR("C1", "complete", false),
    BASE_CTOR("C2", "base", false),

    /** In the ABI; gcc never emits it. */
    ALLOCATING_CTOR("C3", "allocating", false),

    /** gcc's "unified" one, which both of the above call to share code. */
    UNIFIED_CTOR("C4", "unified", false),

    /** gcc >= 7's constructor inherited from a base (`using Base::Base`). */
    COMPLETE_INHERITING_CTOR("CI1", "complete inheriting", false),
    BASE_INHERITING_CTOR("CI2", "base inheriting", false),
    DELETING_DTOR("D0", "deleting", true),
    COMPLETE_DTOR("D1", "complete", true),
    BASE_DTOR("D2", "base", true),
    UNIFIED_DTOR("D4", "unified", true),

    /** MSVC's `??_G`, the slot that destroys and frees one object. */
    SCALAR_DELETING_DTOR("??_G", "scalar deleting", true),

    /** MSVC's `??_E`, which destroys an array of them instead when its flags argument has bit 2 set. */
    VECTOR_DELETING_DTOR("??_E", "vector deleting", true),
    ;

    val isDeleting get() = this == DELETING_DTOR || this == SCALAR_DELETING_DTOR || this == VECTOR_DELETING_DTOR

    /**
     * How the class [className] spells this member in its own body: `Foo`, `~Foo`. Every Itanium variant
     * carries the one source-level name, and Ghidra tells them apart by address; an MSVC deleting
     * destructor goes by the name Ghidra's demangler gives `??_G` or `??_E`.
     */
    fun displayName(className: String) = when (this) {
        SCALAR_DELETING_DTOR -> "`scalar_deleting_destructor'"
        VECTOR_DELETING_DTOR -> "`vector_deleting_destructor'"
        else -> if (isDestructor) "~$className" else className
    }

    companion object {
        private val byCode = entries.associateBy { it.code }

        /** A constructor or destructor name, as gcc's mangle.cc writes them (`write_special_name_constructor`). */
        private val STRUCTOR_CODE = Regex("""CI[12]|C[1-4]|D[0124]""")

        /**
         * Which variant of a constructor or destructor [symbolName] mangles (`_ZN3FooC2Ev` is Foo's base
         * object constructor), or null for any other name. The demangler prints every variant alike, so
         * this asks it where the variant's code sits instead: the one `C1`-like spelling that, with the
         * name cut short before it, still demangles to the same structor of the same class. One inside an
         * identifier (`3AC1`) or a parameter's type cuts the name somewhere else.
         */
        fun of(symbolName: String): StructorVariant? {
            val fn = Demangler.of(symbolName) as? DemangledFunction ?: return null
            return STRUCTOR_CODE.findAll(symbolName).firstNotNullOfOrNull { code ->
                val stub = symbolName.substring(0, code.range.first) + (if (code.value[0] == 'D') "D1Ev" else "C1Ev")
                val probe = Demangler.of(stub) as? DemangledFunction
                val cls = fn.namespace ?: return@firstNotNullOfOrNull null
                // An inheriting constructor demangles under its base's name (`_ZN1BCI21AEi` is `B::A(int)`).
                val sameName = probe?.name == fn.name || code.value.startsWith("CI")
                byCode[code.value].takeIf {
                    probe != null && sameName && probe.namespace?.namespaceString == cls.namespaceString &&
                        // A structor takes its class's name, less template arguments and ABI tags.
                        probe.name.removePrefix("~") == cls.name.substringBefore('<').substringBefore("[abi:")
                }
            }
        }
    }
}

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
 * The constructors and destructors among the functions that store vptrs ([storers]), given the
 * functions vftable slots hold, the classes whose tables hold them ([holders]), and what each function
 * calls on its own `this` ([thisCalls]).
 *
 * A constructor is never virtual, so a slot function that runs a structor on its object is a deleting
 * destructor: one that stores its holders' vptr itself has the destructor inlined, and one that calls
 * a storer of theirs calls the destructor. That store can be a base's: a class whose destructor does
 * nothing before its base's leaves the store of its own vptr out. Telling the other storers apart takes
 * the ABI: under one whose constructors return `this` ([constructorsReturnThis]) the rest are
 * constructors if they do and destructors if they don't; under any other only the destructors a
 * deleting one calls are known.
 *
 * Each comes as the variant it acts as: a [StructorVariant.COMPLETE_CTOR] (MSVC's `??0` builds the whole
 * object, its virtual bases behind a flag), a [StructorVariant.BASE_DTOR] (`??1` leaves those to `??_D`),
 * or a [StructorVariant.DELETING_DTOR], which the ABI's own names tell apart further.
 */
fun structors(
    storers: Map<Function, VptrStores>,
    holders: Map<Function, Set<Address>>,
    thisCalls: (Function) -> Set<Function>,
    ancestors: (Address) -> Set<Address>,
    constructorsReturnThis: Boolean,
): Map<Function, Pair<Address, StructorVariant>> {
    val owners = storers.mapNotNull { (f, s) -> storedClass(s.classes, ancestors)?.let { f to it } }.toMap()
    fun mayDestroy(f: Function) = !constructorsReturnThis || storers[f]?.returnsThis != true

    // The holder whose deleting destructor a slot is, if it tears down a [cls] in the end: [cls] itself, or the
    // one class deriving from it that the others do too, whose own destructor the compiler left no vptr store in.
    fun deleting(held: Set<Address>, cls: Address): Address? {
        val derived = held.filter { it == cls || cls in ancestors(it) }
        return derived.singleOrNull { c -> derived.all { it == c || c in ancestors(it) } }
    }
    val found = mutableMapOf<Function, Pair<Address, StructorVariant>>()
    for ((slot, held) in holders) {
        val own = owners[slot]
        if (own != null) {
            deleting(held, own)?.let { found[slot] = it to StructorVariant.DELETING_DTOR }
            continue
        }
        val dtors = thisCalls(slot).filter(::mayDestroy).mapNotNull { f ->
            owners[f]?.let { cls -> deleting(held, cls)?.let { Triple(f, cls, it) } }
        }
        val (dtor, cls, holder) = dtors.singleOrNull() ?: continue
        found[slot] = holder to StructorVariant.DELETING_DTOR
        found.putIfAbsent(dtor, cls to StructorVariant.BASE_DTOR)
    }
    if (constructorsReturnThis) {
        for ((f, cls) in owners) {
            found.putIfAbsent(f, cls to if (mayDestroy(f)) StructorVariant.BASE_DTOR else StructorVariant.COMPLETE_CTOR)
        }
    }
    return found
}

/**
 * The vptr stores of every function that writes one of [tables], each a vftable's address and the
 * class and subobject offset it serves, and the functions each of those and of some others calls on its
 * own `this`. Off the decompiler: a store counts only through `this`, at the table's own offset, which
 * leaves out a local object built inline (on the stack, or fresh from `operator new`) and a member
 * object's table stored further in; a call, only with `this` for its first argument, which leaves out
 * a method building and destroying a local of a class it has nothing else to do with.
 */
class VptrStoreReader(
    private val program: Program,
    private val tables: Map<Address, Pair<Address, Long>>,
    sink: DiagnosticSink,
) : DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()

    class Reading(val stores: Map<Function, VptrStores>, val thisCalls: Map<Function, Set<Function>>)

    /** The storers' stores, and what they and [others] call on `this`. */
    fun read(others: Collection<Function>, monitor: TaskMonitor): Reading {
        val writes = mutableMapOf<Function, MutableMap<Address, MutableList<Pair<Address, Long>>>>()
        for ((table, served) in tables) {
            for (ref in program.referenceManager.getReferencesTo(table)) {
                val at = ref.fromAddress
                if (program.listing.getInstructionAt(at) == null) continue
                val func = program.functionManager.getFunctionContaining(at) ?: continue
                writes.getOrPut(func) { mutableMapOf() }.getOrPut(at) { mutableListOf() } += served
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
