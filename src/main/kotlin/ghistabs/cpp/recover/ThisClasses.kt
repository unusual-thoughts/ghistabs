package ghistabs.cpp.recover

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.lang.CompilerSpec
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassHierarchyRecords
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.diagnose.DiagnosticSink
import ghistabs.useWith

/**
 * A call passing an object as [callee]'s `this`: [caller]'s own, or one [caller] built with a
 * constructor of class [built].
 */
data class ThisCall(val caller: Function, val callee: Function, val built: GhidraClass? = null)

/** A function's class, as [ThisClassGuesser] guessed it, off [sites] calls. */
data class ThisClassGuess(val cls: GhidraClass, val sites: Int)

/**
 * Guesses the classes of the functions called on objects of the classes in [bases], each with the base it
 * shares its address with. A [GhidraClass] hashes by identity, so each class goes by its one instance among
 * [bases]' keys, and a function's namespace by id.
 */
class ThisClassGuesser(private val bases: Map<GhidraClass, GhidraClass?>) {
    private val byId = bases.keys.associateBy { it.id }
    fun known(f: Function) = byId[f.parentNamespace.id]

    /** [cls], then the base it shares its address with, and so on up. */
    fun addressChain(cls: GhidraClass): List<GhidraClass> = generateSequence(cls) { bases[it] }.take(MAX_DEPTH).toList()

    /**
     * The class of each function [calls] pass an object whose class is known: the caller's own `this`, when
     * the caller is a method of one of [bases], or an object the caller built with a constructor. A method of
     * a class is also called on its derived classes' objects, so where those are of several classes it
     * belongs to the one all the others derive from, through the bases they share their address with, and
     * to none where no one class is.
     */
    fun guess(calls: Collection<ThisCall>): Map<Function, ThisClassGuess> = calls.filter {
        known(it.callee) == null
    }.groupBy { it.callee }.mapNotNull { (f, sites) ->
        val classes = sites.mapNotNull { it.built ?: known(it.caller) }
        val cls = classes.distinct().singleOrNull { c -> classes.all { c in addressChain(it) } }
        cls?.let { f to ThisClassGuess(it, classes.size) }
    }.toMap()
}

private const val MAX_DEPTH = 64

/**
 * [ThisClassGuesser] over a program, for any ABI: every unnamed function in the global namespace whose
 * convention takes `this` (`__thiscall`, or `__fastcall`, whose first argument comes in the same register),
 * off its callers' decompiled calls, against the classes [ClassHierarchyRecords] holds, their methods and the
 * objects their constructors build. Each guess moves the function into its class, a `__fastcall` that takes
 * nothing in EDX becoming a `__thiscall` ([fastcallToThiscall]), and leaves an Analysis bookmark saying where
 * it came from.
 */
class ThisClasses(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()
    private val symbols = program.symbolTable

    /** Each recorded class, with its non-virtual base at offset 0, the one it shares its address with. */
    val bases by lazy {
        val records = program.readClassRecord().orEmpty()
        val classes = records.keys.mapNotNull { id ->
            (symbols.getSymbol(id)?.`object` as? GhidraClass)?.let { id to it }
        }.toMap()
        classes.map { (id, cls) ->
            val base = records.getValue(id).bases.firstOrNull { !it.isVirtual && (it.offset ?: 0L) == 0L }
            cls to base?.namespaceId?.let(classes::get)
        }.toMap()
    }

    /** How many it moved. Only the evidence is decompiled: the recorded classes' methods and constructors' callers. */
    fun guess(monitor: TaskMonitor): Int {
        if (bases.isEmpty() || thisStorage == null) return 0
        val functions = program.functionManager.getFunctions(true).toList()
        val candidates = functions.filterTo(mutableSetOf()) { it.isCandidate() }
        if (candidates.isEmpty()) return 0
        val byId = bases.keys.associateBy { it.id }
        val methods = functions.mapNotNull { f -> byId[f.parentNamespace.id]?.let { f to it } }.toMap()
        // A constructor goes by its class's name, as every ABI's structor pass and stabs name it.
        val ctors = methods.filter { (f, cls) -> f.name == cls.name }
        val calls = buildList {
            DecompInterface().useWith(program) { decomp ->
                for (f in methods.keys + ctors.keys.flatMap { it.getCallingFunctions(monitor) }) {
                    if (monitor.isCancelled) break
                    val high = decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction ?: continue
                    addAll(thisCalls(f, high, ctors).filter { it.callee in candidates })
                }
            }
        }
        return ThisClassGuesser(bases).guess(calls).count { (f, guess) -> place(f, guess) }
    }

    /**
     * An unnamed global function whose first argument comes in where `this` does: under `__thiscall` or
     * `__fastcall` with MSVC, and under `__cdecl` too with MinGW gcc before 4.7, which passes `this` on the stack.
     */
    private fun Function.isCandidate() = parentNamespace.isGlobal && symbol.source == SourceType.DEFAULT &&
        !isThunk && !isExternal && firstArgument() == thisStorage

    private fun Function.firstArgument() = argumentAt(0)

    private fun Function.argumentAt(i: Int) = (callingConvention ?: program.compilerSpec.defaultCallingConvention)
        .getArgLocation(i, null, PointerDataType(program.dataTypeManager), program).firstVarnode?.address

    /**
     * Which of its arguments is `this`: the second where a `__cdecl` function pops one word, which is gcc's
     * hidden pointer for a class returned in memory, and the first otherwise.
     */
    private fun Function.thisIndex() =
        if (callingConventionName == CDECL && stackPurgeSize == program.defaultPointerSize) 1 else 0

    /** The argument a call passes [callee] as its `this`. */
    private fun PcodeOp.thisArgument(callee: Function): Varnode? = callee.thisIndex().let { i ->
        if (numInputs > i + 1) getInput(i + 1) else null
    }

    /** The calls [f] makes on its own `this` and on objects it built with one of [ctors], decompiled as [high]. */
    private fun thisCalls(f: Function, high: HighFunction, ctors: Map<Function, GhidraClass>): List<ThisCall> {
        val self = f.argumentAt(f.thisIndex())
        val ops = high.pcodeOps.asSequence().toList()
        // The objects the function built, by where they point, from their constructor's argument and result.
        val built = buildMap {
            for (op in ops) {
                val ctor = op.directCallee() ?: continue
                val cls = ctors[ctor] ?: continue
                op.thisArgument(ctor)?.let { put(it.pointerInto().key(), cls) }
                op.output?.let { put(it.pointerInto().key(), cls) }
            }
        }
        return ops.mapNotNull { op ->
            val callee = op.directCallee() ?: return@mapNotNull null
            val obj = op.thisArgument(callee)?.pointerInto() ?: return@mapNotNull null
            when {
                !obj.isThis(self) -> built[obj.key()]?.let { ThisCall(f, callee, it) }
                obj.offset == 0L -> ThisCall(f, callee)
                else -> null
            }
        }
    }

    private fun PointerInto.key(): Pair<Any, Long> = (root.def?.seqnum ?: "${root.address}:${root.size}") to offset

    private fun PcodeOp.directCallee(): Function? {
        if (opcode != PcodeOp.CALL || numInputs < 2) return null
        val f = program.functionManager.getFunctionAt(getInput(0).address) ?: return null
        return f.getThunkedFunction(true) ?: f
    }

    private fun place(f: Function, guess: ThisClassGuess): Boolean = runCatching {
        f.parentNamespace = guess.cls
        f.fastcallToThiscall()
        program.bookmarkManager.setBookmark(
            f.entryPoint,
            BookmarkType.ANALYSIS,
            BOOKMARK,
            "Class guessed from ${guess.sites} call(s) on objects of known class",
        )
    }.onFailure {
        warn("this-class-unplaced", "${f.name} -> ${guess.cls.getName(true)}: $it", f.entryPoint)
    }.isSuccess

    companion object {
        const val BOOKMARK = "Method class guess"
        private const val CDECL = CompilerSpec.CALLING_CONVENTION_cdecl
        private const val DECOMPILE_TIMEOUT_SECONDS = 30
    }
}
