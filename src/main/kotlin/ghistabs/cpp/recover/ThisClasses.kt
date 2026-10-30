package ghistabs.cpp.recover

import ghidra.app.decompiler.DecompInterface
import ghidra.program.model.data.Structure
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
import ghistabs.cpp.ClassNaming
import ghistabs.diagnose.DiagnosticSink
import ghistabs.toClass
import ghistabs.useWith

/**
 * What a function does with its own `this`: how far into the object it reads or writes ([extent]),
 * the vftable slots it calls through ([slots]), and the functions it calls on it ([calls]).
 */
data class ThisUse(val extent: Long, val slots: Set<Int>, val calls: Set<Function>)

/**
 * A call passing an object as [callee]'s `this`: [caller]'s own, or one [caller] built with a
 * constructor of class [built].
 */
data class ThisCall(val caller: Function, val callee: Function, val built: GhidraClass? = null)

/** What [ThisClasses] read off the decompiled functions: each one's [uses] of `this`, and the [calls] passing one. */
class ThisReading(val uses: Map<Function, ThisUse>, val calls: Collection<ThisCall>)

/** A function's class, as [ThisClassGuesser] guessed it: [cls], refined up from [common], off [sites] calls. */
data class ThisClassGuess(val cls: GhidraClass, val common: GhidraClass, val sites: Int)

/**
 * A class as the class record holds it, all [ThisClassGuesser] needs of it: the [base] it shares its address
 * with, its [size] range, and how many [slots] the vftable at the start of its object has, where known.
 */
data class ThisClassShape(val base: GhidraClass? = null, val size: LongRange? = null, val slots: Int? = null)

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
     * The most derived class every one of [classes] is, or shares its address with: the first of the
     * first class's [addressChain] that is in every one's.
     */
    fun commonClass(classes: Collection<GhidraClass>): GhidraClass? {
        val chains = classes.map(::addressChain)
        return chains.firstOrNull()?.firstOrNull { c -> chains.all { c in it } }
    }

    /**
     * The class of each function [reading] has called on an object whose class is known: the caller's own
     * `this`, when the caller is a method of one of [shapes] or one guessed here, or an object the caller
     * built with a constructor. Called on objects of several classes, it belongs to their [commonClass]; and
     * then to whichever base that class shares its address with that does all the function does: reaches
     * no further into the object than the base is large (its exact size or, not knowing that, the larger of
     * what its own methods reach and its least size), calls no slot past the end of its vftable, and calls
     * nothing on `this` that belongs to a class below it. Decompiled with `this` as that base, the function
     * would read the same. A function reaching past the common class's exact size is none of its.
     *
     * Guesses feed the next round's callers, until none changes.
     */
    fun guess(reading: ThisReading): Map<Function, ThisClassGuess> {
        val uses = reading.uses
        fun known(f: Function) = byId[f.parentNamespace.id]
        val reach = mutableMapOf<GhidraClass, Long>()
        for ((f, use) in uses) known(f)?.let { reach.merge(it, use.extent, ::maxOf) }
        fun exactSize(cls: GhidraClass) = shapes[cls]?.size?.singleOrNull()
        fun extent(cls: GhidraClass) =
            exactSize(cls) ?: listOfNotNull(reach[cls], shapes[cls]?.size?.first?.takeIf { it > 0 }).maxOrNull()

        val sites = reading.calls.filter { known(it.callee) == null }.groupBy { it.callee }
        var guessed = emptyMap<Function, ThisClassGuess>()
        fun classOf(f: Function) = known(f) ?: guessed[f]?.cls

        fun refine(f: Function, common: GhidraClass): GhidraClass {
            val use = uses[f] ?: return common
            var cls = common
            for (base in addressChain(common).drop(1)) {
                val fits = extent(base)?.let { use.extent <= it } ?: false
                val top = use.slots.maxOrNull()
                val inTable = top == null || shapes[base]?.slots?.let { top < it } ?: false
                val onBase = use.calls.none { g -> g != f && classOf(g)?.let { it !in addressChain(base) } ?: false }
                if (!fits || !inTable || !onBase) break
                cls = base
            }
            return cls
        }

        repeat(MAX_ROUNDS) {
            val next = sites.mapNotNull { (f, calls) ->
                val classes = calls.mapNotNull { it.built ?: classOf(it.caller) }
                val common = commonClass(classes) ?: return@mapNotNull null
                val reaches = uses[f]?.extent ?: 0
                if (exactSize(common)?.let { reaches > it } == true) return@mapNotNull null
                f to ThisClassGuess(refine(f, common), common, classes.size)
            }.toMap()
            if (next == guessed) return next
            guessed = next
        }
        return guessed
    }
}

private const val MAX_ROUNDS = 8
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

    /** How many it moved. */
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
        val callers = candidates.flatMapTo(mutableSetOf()) { it.getCallingFunctions(monitor) }
        val reading = read(candidates + callers + methods.keys, candidates, ctors, monitor)
        return ThisClassGuesser(shapes).guess(reading).count { (f, guess) -> place(f, guess) }
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
            cls to ThisClassShape(base?.let(classes::get), entry.sizeRange(), slotCount(cls))
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

    /** Slots in [cls]'s own vftable, labelled [ClassNaming.VFTABLE]; none where it has several so labelled. */
    private fun slotCount(cls: GhidraClass): Int? {
        val table = symbols.getSymbols(cls).filter { it.name == ClassNaming.VFTABLE }.singleOrNull() ?: return null
        return program.listing.getDataAt(table.address)?.numComponents?.takeIf { it > 0 }
    }

    private fun Function.isCandidate() = parentNamespace.isGlobal && symbol.source == SourceType.DEFAULT &&
        !isThunk && !isExternal && callingConventionName in THIS_CONVENTIONS

    private fun read(
        functions: Set<Function>,
        candidates: Set<Function>,
        ctors: Map<Function, GhidraClass>,
        monitor: TaskMonitor,
    ): ThisReading {
        val uses = mutableMapOf<Function, ThisUse>()
        val calls = mutableListOf<ThisCall>()
        DecompInterface().useWith(program) { decomp ->
            for (f in functions) {
                if (monitor.isCancelled) break
                val high = decomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction ?: continue
                FunctionReading(f, high, ctors).let {
                    uses[f] = it.use
                    calls += it.calls.filter { c -> c.callee in candidates }
                }
            }
        }
        return ThisReading(uses, calls)
    }

    /** One decompiled function's [use] of its `this`, and the [calls] it makes on objects of known class. */
    private inner class FunctionReading(f: Function, high: HighFunction, ctors: Map<Function, GhidraClass>) {
        val calls = mutableListOf<ThisCall>()
        val use: ThisUse

        init {
            val ops = high.pcodeOps.asSequence().toList()
            // The objects the function built, by where they point, from their constructor's argument and result.
            val built = mutableMapOf<Pair<Any, Long>, GhidraClass>()
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
        val cls = guess.cls
        val refined = if (cls != guess.common) ", refined up from ${guess.common.getName(true)}" else ""
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
    }
}
