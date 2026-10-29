package ghistabs.cpp

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.data.Array
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.abi.msvcSubobjectOffset
import ghistabs.diagnose.DiagnosticSink

/**
 * What a function does with its own `this`: how far into the object it reads or writes ([extent]),
 * the vftable slots it calls through ([slots]), and the functions it calls on it ([calls]).
 */
data class ThisUse(val extent: Long, val slots: Set<Int>, val calls: Set<Function>)

/**
 * A call passing an object as [callee]'s `this`: [caller]'s own, or one [caller] built with a
 * constructor of class [built].
 */
data class ThisCall(val caller: Function, val callee: Function, val built: Long? = null)

/** A function's class, as [guessThisClasses] guessed it: [cls], refined up from [common], off [sites] calls. */
data class ThisClassGuess(val cls: Long, val common: Long, val sites: Int)

/**
 * The most derived class every one of [classes] is, or shares its address with: the first of the
 * first class's [chain] (itself, then the base at its offset 0, and so on up) that is in every one's.
 */
fun commonClass(classes: Collection<Long>, chain: (Long) -> List<Long>): Long? {
    val chains = classes.map(chain)
    return chains.firstOrNull()?.firstOrNull { c -> chains.all { c in it } }
}

/**
 * The class each of [candidates] is a method of, off the calls that pass it an object whose class is
 * known: the caller's own `this`, when the caller is a method of a [known] class or one guessed here,
 * or an object the caller built with a constructor. Called on objects of several classes, it belongs
 * to their [commonClass]; and then to whichever base that class shares its address with that does
 * all the method does ([uses]) as well: reaches no further into the object than the base is large
 * ([exactSize]) or, not knowing that, than its own methods reach ([sizeHint] when its struct says
 * more), calls no slot past the end of its vftable ([slotCount]), and calls nothing on `this` that
 * belongs to a class below it. Decompiled with `this` as that base, the method would read the same.
 * A method reaching past the common class's own exact size is none of its.
 *
 * Guesses feed the next round's callers, until none changes. Classes go by their namespaces' ids.
 */
@Suppress("LongParameterList")
fun guessThisClasses(
    candidates: Set<Function>,
    known: Map<Function, Long>,
    calls: Collection<ThisCall>,
    uses: Map<Function, ThisUse>,
    chain: (Long) -> List<Long>,
    slotCount: (Long) -> Int?,
    sizeHint: (Long) -> Long? = { null },
    exactSize: (Long) -> Long? = { null },
): Map<Function, ThisClassGuess> {
    val reach = mutableMapOf<Long, Long>()
    for ((f, cls) in known) uses[f]?.let { reach.merge(cls, it.extent, ::maxOf) }
    fun extent(cls: Long) = exactSize(cls) ?: listOfNotNull(reach[cls], sizeHint(cls)).maxOrNull()

    val sites = calls.filter { it.callee in candidates }.groupBy { it.callee }
    var guessed = emptyMap<Function, ThisClassGuess>()
    fun classOf(f: Function) = known[f] ?: guessed[f]?.cls

    fun refine(f: Function, common: Long): Long {
        val use = uses[f] ?: return common
        var cls = common
        for (base in chain(common).drop(1)) {
            val fits = extent(base)?.let { use.extent <= it } ?: false
            val slots = use.slots.maxOrNull()?.let { top -> slotCount(base)?.let { top < it } ?: false } ?: true
            val calls = use.calls.none { g -> g != f && classOf(g)?.let { it !in chain(base) } ?: false }
            if (!fits || !slots || !calls) break
            cls = base
        }
        return cls
    }

    repeat(MAX_ROUNDS) {
        val next = sites.mapNotNull { (f, calls) ->
            val classes = calls.mapNotNull { it.built ?: classOf(it.caller) }
            val common = commonClass(classes, chain) ?: return@mapNotNull null
            val reaches = uses[f]?.extent ?: 0
            if (exactSize(common)?.let { reaches > it } == true) return@mapNotNull null
            f to ThisClassGuess(refine(f, common), common, classes.size)
        }.toMap()
        if (next == guessed) return next
        guessed = next
    }
    return guessed
}

private const val MAX_ROUNDS = 8

/**
 * [guessThisClasses] over a program: every unnamed function in the global namespace whose convention
 * takes `this` (`__thiscall`, or `__fastcall`, whose first argument comes in the same register), off
 * its callers' decompiled calls, against the classes and bases [ClassHierarchyRecords] holds. Each
 * guess moves the function into its class, a `__fastcall` that takes nothing in EDX becoming a `__thiscall`
 * ([fastcallToThiscall]), and leaves an Analysis bookmark saying where it came from.
 */
class ThisClasses(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()
    private val symbols = program.symbolTable
    private val records = program.readClassRecord().orEmpty()

    private fun namespace(id: Long) = symbols.getSymbol(id)?.`object` as? Namespace

    /** How many it moved. */
    fun guess(monitor: TaskMonitor): Int {
        if (records.isEmpty() || thisStorage == null) return 0
        val functions = program.functionManager.getFunctions(true).toList()
        val known = functions.mapNotNull { f -> f.classId()?.let { f to it } }.toMap()
        val candidates = functions.filterTo(mutableSetOf()) { it.isCandidate() }
        if (candidates.isEmpty()) return 0
        val callers = candidates.flatMapTo(mutableSetOf()) { it.getCallingFunctions(monitor) }
        val methods = known.filterValues { it in records }.keys
        val read = read(candidates + callers + methods, known, monitor)
        val guesses = guessThisClasses(
            candidates,
            known,
            read.calls,
            read.uses,
            ::chain,
            ::slotCount,
            ::structSize,
            ::exactStructSize,
        )
        return guesses.count { (f, guess) -> place(f, guess) }
    }

    private fun Function.isCandidate() = parentNamespace.isGlobal && symbol.source == SourceType.DEFAULT &&
        !isThunk && !isExternal && callingConventionName in THIS_CONVENTIONS

    private fun Function.classId() = (parentNamespace as? GhidraClass)?.id

    /** [cls], then the base it shares its address with: its first direct base that isn't virtual. */
    private fun chain(cls: Long): List<Long> = generateSequence(cls) { k ->
        records[k]?.bases?.firstOrNull { !it.isVirtual }?.namespaceId
    }.take(MAX_DEPTH).toList()

    /** Slots in [cls]'s own vftable: the one at offset 0 of its object, where it has several. */
    private fun slotCount(cls: Long): Int? {
        val ns = namespace(cls) ?: return null
        val tables = symbols.getSymbols(ns).filter { it.name == ClassNaming.VFTABLE }.map { it.address }
        val table = tables.singleOrNull() ?: tables.singleOrNull { program.msvcSubobjectOffset(it) == 0 }
        return (table?.let(program.listing::getDataAt)?.dataType as? Array)?.numElements
    }

    /** As large as the class is sure to be: what its record says, or its struct, whichever says more. */
    private fun structSize(cls: Long): Long? {
        val struct = records[cls]?.structId?.let(program.dataTypeManager::getDataType) as? Structure
        val structLength = struct?.takeUnless { it.isNotYetDefined }?.length?.toLong()
        return listOfNotNull(records[cls]?.size, structLength).maxOrNull()
    }

    /** The class's `sizeof`, where its record has it ([ClassHierarchyRecords.Entry.exactSize]). */
    private fun exactStructSize(cls: Long) = records[cls]?.takeIf { it.exactSize }?.size

    private class Reading(val uses: Map<Function, ThisUse>, val calls: List<ThisCall>)

    private fun read(functions: Set<Function>, known: Map<Function, Long>, monitor: TaskMonitor): Reading {
        val uses = mutableMapOf<Function, ThisUse>()
        val calls = mutableListOf<ThisCall>()
        val ctors = known.filter { (f, cls) -> f.name == namespace(cls)?.name }
        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
            for (f in functions) {
                if (monitor.isCancelled) break
                val high = decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction ?: continue
                FunctionReading(f, high, ctors).let {
                    uses[f] = it.use
                    calls += it.calls
                }
            }
        } finally {
            decomp.dispose()
        }
        return Reading(uses, calls)
    }

    /** One decompiled function's [use] of its `this`, and the [calls] it makes on objects of known class. */
    private inner class FunctionReading(f: Function, high: HighFunction, ctors: Map<Function, Long>) {
        val calls = mutableListOf<ThisCall>()
        val use: ThisUse

        init {
            val ops = high.pcodeOps.asSequence().toList()
            // The objects the function built, by where they point, from their constructor's argument and result.
            val built = mutableMapOf<Pair<Any, Long>, Long>()
            for (op in ops) {
                val cls = op.directCallee()?.let(ctors::get) ?: continue
                built[op.getInput(1).pointerInto().key()] = cls
                op.output?.let { built[it.pointerInto().key()] = cls }
            }
            var extent = 0L
            val slots = mutableSetOf<Int>()
            val onThis = mutableSetOf<Function>()
            for (op in ops) {
                when (op.opcode) {
                    PcodeOp.LOAD -> op.getInput(1).thisOffset()?.let { extent = maxOf(extent, it + op.output.size) }

                    PcodeOp.STORE -> op.getInput(1).thisOffset()?.let {
                        extent = maxOf(extent, it + op.getInput(2).size)
                    }

                    PcodeOp.CALLIND -> op.getInput(0).vcallSlot()?.let { slots += it }

                    PcodeOp.CALL -> {
                        val callee = op.directCallee() ?: continue
                        val obj = op.getInput(1).pointerInto()
                        if (obj.isThis(thisStorage)) {
                            if (obj.offset == 0L) {
                                onThis += callee
                                calls += ThisCall(f, callee)
                            }
                        } else {
                            built[obj.key()]?.let { calls += ThisCall(f, callee, it) }
                        }
                    }
                }
            }
            use = ThisUse(extent, slots, onThis)
        }

        private fun PointerInto.key(): Pair<Any, Long> = (root.def?.seqnum ?: "${root.address}:${root.size}") to offset

        private fun Varnode.thisOffset() = pointerInto().takeIf { it.isThis(thisStorage) }?.offset

        /** The slot a virtual call through `this`'s own vptr reads its target from. */
        private fun Varnode.vcallSlot(): Int? {
            val load = def?.takeIf { it.opcode == PcodeOp.LOAD } ?: return null
            val slot = load.getInput(1).pointerInto()
            val vptr = slot.root.def?.takeIf { it.opcode == PcodeOp.LOAD } ?: return null
            if (vptr.getInput(1).thisOffset() != 0L) return null
            return (slot.offset / program.defaultPointerSize).toInt()
        }

        private fun PcodeOp.directCallee(): Function? {
            if (opcode != PcodeOp.CALL || numInputs < 2) return null
            val f = program.functionManager.getFunctionAt(getInput(0).address) ?: return null
            return f.getThunkedFunction(true) ?: f
        }
    }

    private fun place(f: Function, guess: ThisClassGuess): Boolean {
        val cls = namespace(guess.cls) as? GhidraClass ?: return false
        val refined = if (guess.cls != guess.common) {
            ", refined up from ${namespace(guess.common)?.getName(true)}"
        } else {
            ""
        }
        return runCatching {
            f.parentNamespace = cls
            f.fastcallToThiscall()
            program.bookmarkManager.setBookmark(
                f.entryPoint,
                BookmarkType.ANALYSIS,
                BOOKMARK,
                "Class guessed from ${guess.sites} call(s) on objects of known class$refined",
            )
        }.onFailure { warn("this-class-unplaced", "${f.name} -> ${cls.getName(true)}: $it", f.entryPoint) }
            .isSuccess
    }

    companion object {
        const val BOOKMARK = "Method class guess"
        private val THIS_CONVENTIONS = setOf("__thiscall", "__fastcall")
        private const val DECOMPILE_TIMEOUT_SECONDS = 30
        private const val MAX_DEPTH = 64
    }
}
