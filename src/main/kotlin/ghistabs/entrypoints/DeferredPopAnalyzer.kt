package ghistabs.entrypoints

import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.app.decompiler.DecompInterface
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.SpecExtension
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.block.BasicBlockModel
import ghidra.program.model.block.CodeBlock
import ghidra.program.model.block.CodeBlockIterator
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.lang.PrototypeModel
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.XmlEncode
import ghidra.program.util.ContextEvaluatorAdapter
import ghidra.program.util.SymbolicPropogator
import ghidra.util.task.TaskMonitor

const val DEFERRED_POP_ANALYZER_NAME = "Deferred stack pops (x86)"

/**
 * gcc defers popping a call's arguments (`-fdefer-pop`, on at -O1 and up, and the default for some
 * paths even at -O0) and may never pop them at all when the code ahead only addresses through EBP
 * and the epilogue's `lea -0xc(%ebp),%esp` discards them. Two paths then meet with ESP a few bytes
 * apart:
 *
 * ```
 *   call  operator<<(ostream&, endl)      ; 16 bytes of its arguments still pushed
 *   jmp   0x42306d                        ; ... and joins code the other path reached balanced
 * ```
 *
 * The decompiler cannot give a merge of two stack offsets a stack address, so everything ESP-relative
 * past it decays into a pointer: `puVar7 = &stack0xffffff00`, then every later argument push and
 * return address as a store, `*(undefined4 *)(puVar7 + -0x14) = 0x42350c`, ahead of a call left
 * with no arguments.
 *
 * The bytes left pushed are dead: their call has returned and no later call reads them. So the fix
 * is to pop them where they died — at that call — by giving the call site a prototype whose
 * convention pops that many more bytes (`__cdecl_pop16`: the callee's own model, `extrapop` raised).
 * A call-site override rather than a change to the callee, because the callee is called balanced
 * everywhere else; and a derived *convention*, installed as a spec extension like
 * [StructReturnAnalyzer]'s, because extrapop is all an override can carry.
 *
 * ESP comes from Ghidra's own constant propagation, which is not the decompiler and can disagree with
 * it (a merge nothing past reads ESP from, a callee whose purge the decompiler works out differently),
 * so each function's fix is kept only if the decompiler then makes fewer stores through pointers than
 * it did before. Propagation records each instruction's end state only from Ghidra 11.4, so before
 * it only the import purges below are fixed.
 *
 * MinGW's import stubs give it a second source of the same mismatch: `_Sleep@4` thunks to an
 * external `Sleep` whose purge Ghidra records as 0 against the 4 the `@4` says it pops, so every path
 * through a Win32 call comes back 4 bytes too deep. Those purges are read off the stub's name first.
 */
class DeferredPopAnalyzer :
    AbstractAnalyzer(
        DEFERRED_POP_ANALYZER_NAME,
        "Pop arguments gcc left on the stack at a call, where two paths would meet with ESP apart.",
        AnalyzerType.FUNCTION_ANALYZER,
    ) {
    init {
        // After every pass that settles a callee's signature or convention — the Stabs Importer (LOW)
        // and [StructReturnAnalyzer] — since an override freezes the callee's signature as it stands.
        priority = AnalysisPriority.LOW_PRIORITY.after().after().after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program?) = program?.run {
        language.processor.toString() == "x86" && !language.isBigEndian && defaultPointerSize == 4
    } ?: false

    override fun added(program: Program?, set: AddressSetView?, monitor: TaskMonitor?, log: MessageLog?): Boolean {
        program ?: return false
        val mon = monitor ?: TaskMonitor.DUMMY
        val stdcall = fixImportPurges(program)
        if (stdcall > 0) log?.appendMsg(DEFERRED_POP_ANALYZER_NAME, "set the purge of $stdcall stdcall import(s)")

        val plans = program.functionManager.getFunctions(set, true)
            .filterNot { it.isThunk || it.isExternal || hasPopOverrides(program, it) }
            .mapNotNull { f ->
                mon.checkCancelled()
                plan(program, f, mon)?.let { f to it }
            }
        plans.forEach { (_, plan) -> plan.unfixed.forEach { (merge, into) -> bookmarkUnfixed(program, merge, into) } }
        val fixable = plans.filter { it.second.pops.isNotEmpty() }
        if (fixable.isEmpty()) return true

        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
            val kept = fixable.count { (f, plan) -> apply(program, decomp, f, plan.pops, mon, log) }
            if (kept > 0) log?.appendMsg(DEFERRED_POP_ANALYZER_NAME, "popped deferred arguments in $kept function(s)")
        } finally {
            decomp.dispose()
        }
        return true
    }

    private fun apply(
        program: Program,
        decomp: DecompInterface,
        f: Function,
        pops: Map<Address, Pop>,
        monitor: TaskMonitor,
        log: MessageLog?,
    ): Boolean {
        val before = decomp.pointerStores(f, monitor) ?: return false
        val written = pops.mapNotNull { (call, pop) -> override(program, f, call, pop.extra, log)?.let { call to it } }
        if (written.isEmpty()) return false
        val after = decomp.pointerStores(f, monitor)
        val kept = after != null && after < before
        if (kept) {
            for ((call, convention) in written) {
                bookmarkCall(
                    program,
                    call,
                    convention,
                    pops.getValue(call),
                    before,
                    after,
                )
            }
        } else {
            removeOverrides(program, f, written.map { it.first }.toSet())
        }
        bookmarkMerges(program, pops, kept, before, after)
        return kept
    }
}

/** Bytes a call is made to pop beyond its convention, and the merges whose ESP mismatch that evens out. */
private data class Pop(val extra: Int, val joins: Set<Address>)

/** What [plan] found in a function: the pops to try, and the merges left apart with the ESP each way brings. */
private data class Plan(val pops: Map<Address, Pop>, val unfixed: Map<Address, Map<Address, Long>>)

/** Bookmark categories, one per kind, so two kinds at one address don't replace each other. */
internal const val CALL_BOOKMARK = "$DEFERRED_POP_ANALYZER_NAME: call"
internal const val MERGE_BOOKMARK = "$DEFERRED_POP_ANALYZER_NAME: merge"
internal const val UNFIXED_BOOKMARK = "$DEFERRED_POP_ANALYZER_NAME: unfixed merge"
internal const val IMPORT_BOOKMARK = "$DEFERRED_POP_ANALYZER_NAME: stdcall import"

/** Says at [call] what its override pops and why, since nothing in the listing shows a call-site prototype. */
private fun bookmarkCall(program: Program, call: Address, convention: String, pop: Pop, before: Int, after: Int) =
    program.bookmarkManager.setBookmark(
        call,
        BookmarkType.ANALYSIS,
        CALL_BOOKMARK,
        "$convention: this call pops ${pop.extra} more bytes than its callee's convention. gcc left that many " +
            "bytes of arguments pushed here (a deferred pop) and the path reaches ${pop.joins.joinToString()} " +
            "with ESP ${pop.extra} deeper than the others, which makes the decompiler lose the stack there. " +
            "Popping the dead arguments at this call evens ESP out (stores through pointers in this " +
            "function: $before -> $after).",
    )

/** Says at each merge [pops] are for which calls pop for it, or that it stays apart if the decompiler rejected them. */
private fun bookmarkMerges(program: Program, pops: Map<Address, Pop>, kept: Boolean, before: Int, after: Int?) {
    val callsByMerge = pops.flatMap { (call, pop) -> pop.joins.map { it to call } }.groupBy({ it.first }, { it.second })
    for ((merge, calls) in callsByMerge) {
        val at = calls.joinToString { "$it (${pops.getValue(it).extra} bytes)" }
        if (kept) {
            program.bookmarkManager.setBookmark(
                merge,
                BookmarkType.ANALYSIS,
                MERGE_BOOKMARK,
                "Paths meet here with ESP apart, because gcc left call arguments pushed on the deeper ones. " +
                    "Evened out by popping them at $at.",
            )
        } else {
            program.bookmarkManager.setBookmark(
                merge,
                BookmarkType.WARNING,
                UNFIXED_BOOKMARK,
                "Paths meet here with ESP apart. Popping the leftover arguments at $at was tried, but the " +
                    "decompiler's stores through pointers in this function went $before -> $after rather than " +
                    "down, so it was undone.",
            )
        }
    }
}

/** Says at [merge] that paths meet with ESP apart and nothing could pop the difference, so what follows may decay. */
private fun bookmarkUnfixed(program: Program, merge: Address, into: Map<Address, Long>) =
    program.bookmarkManager.setBookmark(
        merge,
        BookmarkType.WARNING,
        UNFIXED_BOOKMARK,
        "Paths meet here with ESP apart (ESP ${into.entries.joinToString { (from, sp) -> "$sp from $from" }}, " +
            "relative to entry), and on some way in no call's arguments account for the extra bytes, so nothing " +
            "was popped. The decompiler may turn stack accesses past this point into stores through a pointer.",
    )

/** MinGW import stubs `_Name@N` whose external target records a purge other than the `N` it pops. */
internal fun fixImportPurges(program: Program): Int = program.functionManager.getFunctions(true).count { stub ->
    val pops = STDCALL_SUFFIX.find(stub.name)?.groupValues?.get(1)?.toInt()
    val target = if (stub.isThunk) stub.getThunkedFunction(true) else null
    if (pops == null || target == null || !target.isExternal || target.stackPurgeSize == pops) return@count false
    program.bookmarkManager.setBookmark(
        stub.entryPoint,
        BookmarkType.ANALYSIS,
        IMPORT_BOOKMARK,
        "${target.name} is stdcall: the @$pops in ${stub.name} says it pops $pops bytes of arguments, but Ghidra " +
            "recorded ${target.stackPurgeSize} for the import. Set to $pops, or every path through a call to it " +
            "comes back $pops bytes deep and meets the others with ESP apart.",
    )
    target.stackPurgeSize = pops
    true
}

private val STDCALL_SUFFIX = Regex("@(\\d+)$")

/** Stores the decompiler makes through a pointer — what an untracked stack pointer turns pushes into. */
private fun DecompInterface.pointerStores(f: Function, monitor: TaskMonitor): Int? =
    decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, monitor).highFunction?.stores()

private fun HighFunction.stores() = pcodeOps.asSequence().count { it.opcode == PcodeOp.STORE }

private const val DECOMPILE_TIMEOUT_SECONDS = 60

/** Writes the call-site prototype popping [extra] more at [call]; the convention it uses, or null if it can't. */
private fun override(program: Program, caller: Function, call: Address, extra: Int, log: MessageLog?) = runCatching {
    val callee = program.listing.getInstructionAt(call).flows.single().let { program.functionManager.getFunctionAt(it) }
    val base =
        callee.callingConventionName.takeUnless {
            it == Function.UNKNOWN_CALLING_CONVENTION_STRING ||
                it == Function.DEFAULT_CALLING_CONVENTION_STRING
        }
            ?: program.compilerSpec.defaultCallingConvention.name
    val model = requireNotNull(program.compilerSpec.getCallingConvention(base)) { "no calling convention $base" }
    require(model.extrapop != PrototypeModel.UNKNOWN_EXTRAPOP) { "$base pops an unknown amount" }
    val name = "$base$POP_SUFFIX$extra"
    if (program.compilerSpec.getCallingConvention(name) == null) {
        SpecExtension(
            program,
        ).addReplaceCompilerSpecExtension(poppingConventionXml(program, model, name, extra), TaskMonitor.DUMMY)
    }
    val sig = FunctionDefinitionDataType(callee.getSignature(true), program.dataTypeManager)
    sig.setCallingConvention(name)
    HighFunctionDBUtil.writeOverride(caller, call, sig)
    name
}.getOrElse {
    log?.appendMsg(DEFERRED_POP_ANALYZER_NAME, "no override at $call in ${caller.name}: ${it.message}")
    null
}

private const val POP_SUFFIX = "_pop"

private fun removeOverrides(program: Program, f: Function, calls: Set<Address>) {
    val space = HighFunction.findOverrideSpace(f) ?: return
    program.symbolTable.getSymbols(space).filter { it.address in calls }.forEach { it.delete() }
}

/** [model] re-encoded under [name], popping [extra] more bytes. See [derivedConventionXml]. */
private fun poppingConventionXml(program: Program, model: PrototypeModel, name: String, extra: Int): String {
    val encoded = XmlEncode().apply { model.encode(this, program.compilerSpec.pcodeInjectLibrary) }.toString()
    return encoded
        .replaceFirst(Regex("name=\"[^\"]*\""), "name=\"$name\"")
        .replaceFirst(Regex("extrapop=\"-?\\d+\""), "extrapop=\"${model.extrapop + extra}\"")
}

/** Whether an earlier run already popped deferred arguments in [f]: its fix stands, as the oracle judged it. */
private fun hasPopOverrides(program: Program, f: Function) = HighFunction.findOverrideSpace(f)?.let { space ->
    program.symbolTable.getSymbols(space).any { sym ->
        (HighFunctionDBUtil.readOverride(sym)?.dataType as? FunctionSignature)?.callingConventionName
            ?.contains(POP_SUFFIX) == true
    }
} ?: false

/**
 * Calls to make pop more, and by how much, so that no two paths into a block arrive with ESP apart;
 * null if there are none. A pop moves ESP at every merge past it, so each round feeds the pops
 * planned so far back to Ghidra's propagation as stack-depth overrides on their calls, and fixes the
 * first merge still apart. The overrides are scratch, gone again on return: the decompiler reads
 * them per callee, not per call, so what it gets is the call-site prototype [override] writes.
 */
private fun plan(program: Program, f: Function, monitor: TaskMonitor): Plan? {
    if (CallDepthChangeInfo.getStackDepthChanges(program, f.body).hasNext()) return null
    val pops = mutableMapOf<Address, Int>()
    val joins = mutableMapOf<Address, MutableSet<Address>>()
    val stuck = mutableMapOf<Address, Map<Address, Long>>()
    fun planned() = Plan(pops.mapValues { (call, extra) -> Pop(extra, joins[call].orEmpty()) }, stuck.toMap())
    try {
        repeat(MAX_ROUNDS) {
            val esp = Esp.of(program, f, monitor) ?: return null
            val (merge, into) = esp.merges().firstOrNull { it.first !in stuck } ?: return planned().takeIf {
                it.pops.isNotEmpty() || it.unfixed.isNotEmpty()
            }
            val shallow = into.values.max()
            val fixes = into.filterValues { it != shallow }.map { (from, deep) ->
                esp.culprits(from, deep)?.map { it to (shallow - deep).toInt() }
            }
            if (fixes.any { it == null }) {
                stuck[merge] = into
            } else {
                fixes.flatMap { it.orEmpty() }.distinct().forEach { (call, extra) ->
                    CallDepthChangeInfo.setStackDepthChange(program, call, pops.merge(call, extra, Int::plus)!!)
                    joins.getOrPut(call) { mutableSetOf() } += merge
                }
            }
        }
        return planned()
    } finally {
        pops.keys.forEach { CallDepthChangeInfo.removeStackDepthChange(program, it) }
    }
}

private const val MAX_ROUNDS = 32

/**
 * ESP at each instruction of [f], relative to entry, as Ghidra's constant propagation tracks it —
 * set up the way [CallDepthChangeInfo] sets it up, which offers only the start of each instruction
 * where a merge needs what each predecessor leaves at its end.
 */
private class Esp(private val program: Program, private val f: Function, private val values: SymbolicPropogator) {
    private val sp = program.compilerSpec.stackPointer
    private val blocks = BasicBlockModel(program)

    /** Blocks that paths enter with ESP apart, in address order, each with the ESP its predecessors leave. */
    fun merges(): List<Pair<Address, Map<Address, Long>>> =
        blocks.getCodeBlocksContaining(f.body, TaskMonitor.DUMMY).asSequence().mapNotNull { block ->
            val into = block.preds().mapNotNull { pred ->
                val last = program.listing.getInstructionContaining(pred.maxAddress) ?: return@mapNotNull null
                values.valueAfter(last.address, sp)?.depth()?.let { pred.firstStartAddress to it }
            }.toMap()
            (block.firstStartAddress to into).takeIf { into.values.toSet().size > 1 }
        }.sortedBy { it.first }.toList()

    /**
     * The calls whose arguments are what the path out of block [from] still has pushed: on each way
     * back, the last call before which ESP stood at [deep]. A call that pushes and pops its own
     * arguments in between is passed over, since the bytes predate it. Null where a way back has none.
     */
    fun culprits(from: Address, deep: Long, seen: MutableSet<Address> = mutableSetOf()): List<Address>? {
        if (!seen.add(from)) return emptyList()
        val block = blocks.getCodeBlockAt(from, TaskMonitor.DUMMY) ?: return null
        val call = program.listing.getInstructions(block, true).lastOrNull {
            it.flowType.isCall && values.getRegisterValue(it.address, sp)?.depth() == deep
        }
        if (call != null) {
            val callee = call.flows.singleOrNull()?.let { program.functionManager.getFunctionAt(it) }
            return if (callee == null) null else listOf(call.address)
        }
        val preds = block.preds().takeIf { it.isNotEmpty() } ?: return null
        return preds.flatMap { culprits(it.firstStartAddress, deep, seen) ?: return null }
    }

    private fun SymbolicPropogator.Value.depth() = value.takeIf { relativeRegister == sp }

    private fun CodeBlockIterator.asSequence() = generateSequence { if (hasNext()) next() else null }

    /** Blocks flowing into this one inside [f], calls aside. */
    private fun CodeBlock.preds() = getSources(TaskMonitor.DUMMY).let { refs ->
        generateSequence { if (refs.hasNext()) refs.next() else null }
            .filter { !it.flowType.isCall && f.body.contains(it.sourceAddress) }
            .map { it.sourceBlock }
            .toList()
    }

    companion object {
        fun of(program: Program, f: Function, monitor: TaskMonitor): Esp? {
            val values = endStatePropagator(program) ?: return null
            values.setParamRefCheck(false)
            values.setReturnRefCheck(false)
            values.setStoredRefCheck(false)
            values.setRegister(f.entryPoint, program.compilerSpec.stackPointer)
            values.flowConstants(f.entryPoint, f.body, ContextEvaluatorAdapter(), true, monitor)
            return Esp(program, f, values)
        }
    }
}
