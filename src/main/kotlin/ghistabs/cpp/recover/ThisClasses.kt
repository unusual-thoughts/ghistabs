package ghistabs.cpp.recover

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
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

/** How far into its own `this` a function reads or writes. */
data class ThisUse(val extent: Long)

/**
 * A call passing an object as [callee]'s `this`: [caller]'s own, or one [caller] built with a
 * constructor of class [built].
 */
data class ThisCall(val caller: Function, val callee: Function, val built: GhidraClass? = null)

/** What [ThisClasses] read off the decompiled functions: each one's [uses] of `this`, and the [calls] passing one. */
class ThisReading(val uses: Map<Function, ThisUse>, val calls: Collection<ThisCall>)

/** A function's class, as [ThisClassGuesser] guessed it, off [sites] calls. */
data class ThisClassGuess(val cls: GhidraClass, val sites: Int)

/**
 * A class as the class record holds it, all [ThisClassGuesser] needs of it: the [base] it shares its address
 * with, and its [size] range.
 */
data class ThisClassShape(val base: GhidraClass? = null, val size: LongRange? = null)

/**
 * Guesses the classes of the functions called on objects of the classes in [shapes]. A [GhidraClass] hashes
 * by identity, so each class goes by its one instance among [shapes]' keys, and a function's namespace by id.
 */
class ThisClassGuesser(private val shapes: Map<GhidraClass, ThisClassShape>) {
    private val byId = shapes.keys.associateBy { it.id }

    /** [cls], then the base it shares its address with, and so on up. */
    fun addressChain(cls: GhidraClass): List<GhidraClass> =
        generateSequence(cls) { shapes[it]?.base }.take(MAX_DEPTH).toList()

    /**
     * The class of each function [reading] has called on an object whose class is known: the caller's own
     * `this`, when the caller is a method of one of [shapes], or an object the caller built with a
     * constructor. A method of a class is also called on its derived classes' objects, so where those are
     * of several classes it belongs to the one all the others derive from, through the bases they share
     * their address with, and to none where no one class is. A function reaching past that class's exact
     * size is none of its.
     */
    fun guess(reading: ThisReading): Map<Function, ThisClassGuess> {
        fun known(f: Function) = byId[f.parentNamespace.id]
        return reading.calls.filter { known(it.callee) == null }.groupBy { it.callee }.mapNotNull { (f, calls) ->
            val classes = calls.mapNotNull { it.built ?: known(it.caller) }
            val cls = classes.distinct().singleOrNull { c -> classes.all { c in addressChain(it) } }
                ?: return@mapNotNull null
            val size = shapes[cls]?.size?.singleOrNull()
            if (size != null && (reading.uses[f]?.extent ?: 0) > size) return@mapNotNull null
            f to ThisClassGuess(cls, classes.size)
        }.toMap()
    }
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

    /**
     * How many it moved. Only what holds evidence is decompiled: the recorded classes' methods and the
     * callers of their constructors, and then each function guessed, for how far it reaches.
     */
    fun guess(monitor: TaskMonitor): Int {
        val shapes = shapes()
        if (shapes.isEmpty() || thisStorage == null) return 0
        val functions = program.functionManager.getFunctions(true).toList()
        val candidates = functions.filterTo(mutableSetOf()) { it.isCandidate() }
        if (candidates.isEmpty()) return 0
        val byId = shapes.keys.associateBy { it.id }
        val methods = functions.mapNotNull { f -> byId[f.parentNamespace.id]?.let { f to it } }.toMap()
        // A constructor goes by its class's name, as every ABI's structor pass and stabs name it.
        val ctors = methods.filter { (f, cls) -> f.name == cls.name }
        val guesser = ThisClassGuesser(shapes)
        val uses = mutableMapOf<Function, ThisUse>()
        val calls = mutableListOf<ThisCall>()
        var guesses = emptyMap<Function, ThisClassGuess>()
        DecompInterface().useWith(program) { decomp ->
            fun read(fs: Collection<Function>) {
                for (f in fs) {
                    if (monitor.isCancelled) return
                    val high = decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction
                    val reading = FunctionReading(f, high ?: continue, ctors)
                    uses[f] = reading.use
                    calls += reading.calls.filter { it.callee in candidates }
                }
            }
            read(methods.keys + ctors.keys.flatMap { it.getCallingFunctions(monitor) })
            read(guesser.guess(ThisReading(uses, calls)).keys - uses.keys)
            guesses = guesser.guess(ThisReading(uses, calls))
        }
        return guesses.count { (f, guess) -> place(f, guess) }
    }

    /** Each recorded class's shape, the base it shares its address with being its non-virtual one at offset 0. */
    private fun shapes(): Map<GhidraClass, ThisClassShape> {
        val records = program.readClassRecord().orEmpty()
        val classes = records.keys.mapNotNull { id ->
            (symbols.getSymbol(id)?.`object` as? GhidraClass)?.let { id to it }
        }.toMap()
        return classes.map { (id, cls) ->
            val entry = records.getValue(id)
            val base = entry.bases.firstOrNull { !it.isVirtual && (it.offset ?: 0L) == 0L }?.namespaceId
            cls to ThisClassShape(base?.let(classes::get), entry.sizeRange())
        }.toMap()
    }

    /** The record's size, or its struct's where that says more; unbounded above unless exact. */
    private fun ClassHierarchyRecords.Entry.sizeRange(): LongRange? {
        if (exactSize && size != null) return size..size
        val struct = structId?.let(program.dataTypeManager::getDataType) as? Structure
        val structLength = struct?.takeUnless { it.isNotYetDefined }?.length?.toLong()
        val least = listOfNotNull(size, structLength).maxOrNull() ?: return null
        return least..Long.MAX_VALUE
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

    /** One decompiled function's [use] of its `this`, and the [calls] it makes on objects of known class. */
    private inner class FunctionReading(f: Function, high: HighFunction, ctors: Map<Function, GhidraClass>) {
        private val self = f.argumentAt(f.thisIndex())
        val calls = mutableListOf<ThisCall>()
        val use: ThisUse

        init {
            val ops = high.pcodeOps.asSequence().toList()
            // The objects the function built, by where they point, from their constructor's argument and result.
            val built = mutableMapOf<Pair<Any, Long>, GhidraClass>()
            for (op in ops) {
                val ctor = op.directCallee() ?: continue
                val cls = ctors[ctor] ?: continue
                op.thisArgument(ctor)?.let { built[it.pointerInto().key()] = cls }
                op.output?.let { built[it.pointerInto().key()] = cls }
            }
            var extent = 0L
            for (op in ops) {
                when (op.opcode) {
                    PcodeOp.LOAD -> op.getInput(1).thisOffset()?.let { extent = maxOf(extent, it + op.output.size) }

                    PcodeOp.STORE -> op.getInput(1).thisOffset()?.let {
                        extent = maxOf(extent, it + op.getInput(2).size)
                    }

                    PcodeOp.CALL -> {
                        val callee = op.directCallee() ?: continue
                        val obj = op.thisArgument(callee)?.pointerInto() ?: continue
                        if (obj.isThis(self)) {
                            if (obj.offset == 0L) calls += ThisCall(f, callee)
                        } else {
                            built[obj.key()]?.let { calls += ThisCall(f, callee, it) }
                        }
                    }
                }
            }
            use = ThisUse(extent)
        }

        private fun PointerInto.key(): Pair<Any, Long> = (root.def?.seqnum ?: "${root.address}:${root.size}") to offset

        private fun Varnode.thisOffset() = pointerInto().takeIf { it.isThis(self) }?.offset

        private fun PcodeOp.directCallee(): Function? {
            if (opcode != PcodeOp.CALL || numInputs < 2) return null
            val f = program.functionManager.getFunctionAt(getInput(0).address) ?: return null
            return f.getThunkedFunction(true) ?: f
        }
    }

    private fun place(f: Function, guess: ThisClassGuess): Boolean {
        val cls = guess.cls
        return runCatching {
            f.parentNamespace = cls
            f.fastcallToThiscall()
            program.bookmarkManager.setBookmark(
                f.entryPoint,
                BookmarkType.ANALYSIS,
                BOOKMARK,
                "Class guessed from ${guess.sites} call(s) on objects of known class",
            )
        }.onFailure { warn("this-class-unplaced", "${f.name} -> ${cls.getName(true)}: $it", f.entryPoint) }
            .isSuccess
    }

    companion object {
        const val BOOKMARK = "Method class guess"
        private const val CDECL = CompilerSpec.CALLING_CONVENTION_cdecl
        private const val DECOMPILE_TIMEOUT_SECONDS = 30
    }
}
