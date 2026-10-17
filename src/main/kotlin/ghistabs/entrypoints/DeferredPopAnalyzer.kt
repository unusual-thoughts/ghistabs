package ghistabs.entrypoints

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
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.lang.PrototypeModel
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode
import ghidra.program.model.pcode.XmlEncode
import ghidra.util.task.TaskMonitor

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
 * The walk over ESP is a model of the decompiler's, not the decompiler itself, and the two can
 * disagree (a callee whose purge Ghidra's solver later works out differently, say), so each function's
 * fix is kept only if the decompiler then makes fewer stores through pointers than it did before.
 *
 * MinGW's import stubs give it a second source of the same mismatch: `_Sleep@4` thunks to an
 * external `Sleep` whose purge Ghidra records as 0 against the 4 the `@4` says it pops, so every path
 * through a Win32 call comes back 4 bytes too deep. Those purges are read off the stub's name first.
 */
class DeferredPopAnalyzer :
    AbstractAnalyzer(
        NAME,
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

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        val stdcall = program.fixImportPurges()
        if (stdcall > 0) log.appendMsg(NAME, "set the purge of $stdcall stdcall import(s)")

        val plans = program.functionManager.getFunctions(set, true)
            .filterNot { it.isThunk || it.isExternal }
            .mapNotNull { f ->
                monitor.checkCancelled()
                EspWalk(program, f).plan()?.let { f to it }
            }
        plans.forEach { (_, plan) -> plan.unfixed.forEach { (merge, into) -> program.bookmarkUnfixed(merge, into) } }
        val fixable = plans.filter { it.second.pops.isNotEmpty() }
        if (fixable.isEmpty()) return true

        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
            val kept = fixable.count { (f, plan) -> program.applyExtraPops(decomp, f, plan.pops, monitor, log) }
            if (kept > 0) log.appendMsg(NAME, "popped deferred arguments in $kept function(s)")
        } finally {
            decomp.dispose()
        }
        return true
    }

    companion object {
        const val NAME = "Deferred stack pops (x86)"
    }
}

private fun Program.applyExtraPops(
    decomp: DecompInterface,
    f: Function,
    pops: Map<Address, Pop>,
    monitor: TaskMonitor,
    log: MessageLog,
): Boolean {
    val before = decomp.pointerStores(f, monitor) ?: return false
    val written = pops.mapNotNull { (call, pop) -> override(f, call, pop.extra, log)?.let { call to it } }
    if (written.isEmpty()) return false
    val after = decomp.pointerStores(f, monitor)
    val kept = after != null && after < before
    if (kept) {
        for ((call, convention) in written) {
            bookmarkCall(
                call,
                convention,
                pops.getValue(call),
                before,
                after,
            )
        }
    } else {
        removeOverrides(f, written.map { it.first }.toSet())
    }
    bookmarkMerges(pops, kept, before, after)
    return kept
}

/** Bytes a call is made to pop beyond its convention, and the merges whose ESP mismatch that evens out. */
private data class Pop(val extra: Int, val joins: Set<Address>)

/** What [EspWalk] found in a function: the pops to try, and the merges left apart with the ESP each way brings. */
private data class Plan(val pops: Map<Address, Pop>, val unfixed: Map<Address, Map<Address, Long>>)

/** Bookmark categories, one per kind, so two kinds at one address don't replace each other. */
internal const val CALL_BOOKMARK = "${DeferredPopAnalyzer.NAME}: call"
internal const val MERGE_BOOKMARK = "${DeferredPopAnalyzer.NAME}: merge"
internal const val UNFIXED_BOOKMARK = "${DeferredPopAnalyzer.NAME}: unfixed merge"
internal const val IMPORT_BOOKMARK = "${DeferredPopAnalyzer.NAME}: stdcall import"

/** Says at [call] what its override pops and why, since nothing in the listing shows a call-site prototype. */
private fun Program.bookmarkCall(call: Address, convention: String, pop: Pop, before: Int, after: Int) =
    bookmarkManager.setBookmark(
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
private fun Program.bookmarkMerges(pops: Map<Address, Pop>, kept: Boolean, before: Int, after: Int?) {
    val callsByMerge = pops.flatMap { (call, pop) -> pop.joins.map { it to call } }.groupBy({ it.first }, { it.second })
    for ((merge, calls) in callsByMerge) {
        val at = calls.joinToString { "$it (${pops.getValue(it).extra} bytes)" }
        if (kept) {
            bookmarkManager.setBookmark(
                merge,
                BookmarkType.ANALYSIS,
                MERGE_BOOKMARK,
                "Paths meet here with ESP apart, because gcc left call arguments pushed on the deeper ones. " +
                    "Evened out by popping them at $at.",
            )
        } else {
            bookmarkManager.setBookmark(
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
private fun Program.bookmarkUnfixed(merge: Address, into: Map<Address, Long>) = bookmarkManager.setBookmark(
    merge,
    BookmarkType.WARNING,
    UNFIXED_BOOKMARK,
    "Paths meet here with ESP apart (ESP ${into.entries.joinToString { (from, sp) -> "$sp from $from" }}, " +
        "relative to entry), and on some way in no call's arguments account for the extra bytes, so nothing " +
        "was popped. The decompiler may turn stack accesses past this point into stores through a pointer.",
)

/** MinGW import stubs `_Name@N` whose external target records a purge other than the `N` it pops. */
internal fun Program.fixImportPurges(): Int = functionManager.getFunctions(true).count { stub ->
    val pops = STDCALL_SUFFIX.find(stub.name)?.groupValues?.get(1)?.toInt()
    val target = if (stub.isThunk) stub.getThunkedFunction(true) else null
    if (pops == null || target == null || !target.isExternal || target.stackPurgeSize == pops) return@count false
    bookmarkManager.setBookmark(
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
private fun Program.override(caller: Function, call: Address, extra: Int, log: MessageLog) = runCatching {
    val callee = listing.getInstructionAt(call).flows.single().let { functionManager.getFunctionAt(it) }
    val model = callee.callingConvention ?: compilerSpec.defaultCallingConvention
    require(model.extrapop != PrototypeModel.UNKNOWN_EXTRAPOP) { "${model.name} pops an unknown amount" }
    "${model.name}_pop$extra".also { ccName ->
        if (compilerSpec.getCallingConvention(ccName) == null) {
            SpecExtension(this)
                .addReplaceCompilerSpecExtension(poppingConventionXml(model, ccName, extra), TaskMonitor.DUMMY)
        }
        val sig = FunctionDefinitionDataType(callee.getSignature(true), dataTypeManager).apply {
            setCallingConvention(ccName)
        }
        HighFunctionDBUtil.writeOverride(caller, call, sig)
    }
}.onFailure { log.appendMsg(DeferredPopAnalyzer.NAME, "no override at $call in ${caller.name}: ${it.message}") }
    .getOrNull()

private fun Program.removeOverrides(f: Function, calls: Set<Address>) {
    val space = HighFunction.findOverrideSpace(f) ?: return
    symbolTable.getSymbols(space).filter { it.address in calls }.forEach { it.delete() }
}

/** [model] re-encoded under [name], popping [extra] more bytes. See [derivedConventionXml]. */
private fun Program.poppingConventionXml(model: PrototypeModel, name: String, extra: Int) =
    XmlEncode().apply { model.encode(this, compilerSpec.pcodeInjectLibrary) }.toString()
        .replaceFirst(Regex("name=\"[^\"]*\""), "name=\"$name\"")
        .replaceFirst(Regex("extrapop=\"-?\\d+\""), "extrapop=\"${model.extrapop + extra}\"")

/**
 * ESP, as an offset from its value at entry, at every block of [f] — tracked through the p-code the
 * way the decompiler does, by constant adds and subtracts, a call moving it by the callee's
 * convention plus purge, `and esp, -16` read as a copy, and nothing else.
 */
private class EspWalk(private val program: Program, private val f: Function) {
    private val esp = Varnode(program.language.getRegister("ESP").address, 4)
    private val blocks = BasicBlockModel(program)

    private val pops = mutableMapOf<Address, Int>()
    private val joins = mutableMapOf<Address, MutableSet<Address>>()

    /** Call sites already overridden, ours from an earlier run included, with what their convention pops. */
    private val overridden: Map<Address, Int> = HighFunction.findOverrideSpace(f)?.let { space ->
        program.symbolTable.getSymbols(space).mapNotNull { sym ->
            (HighFunctionDBUtil.readOverride(sym)?.dataType as? FunctionSignature)
                ?.callingConventionName
                ?.let { program.compilerSpec.getCallingConvention(it) }?.extrapop
                ?.takeIf { it != PrototypeModel.UNKNOWN_EXTRAPOP }?.let { sym.address to it - 4 }
        }.toMap()
    } ?: emptyMap()
    private lateinit var entry: MutableMap<Address, Long>
    private lateinit var depthAtCall: MutableMap<Address, Long>
    private lateinit var incoming: MutableMap<Address, MutableMap<Address, Long>>
    private var conflict: Address? = null

    /** Merges with no call to pop at on some way in: passed over, so the rest of the function is still fixed. */
    private val stuck = mutableMapOf<Address, Map<Address, Long>>()

    /**
     * Calls to make pop more, and by how much, so that no two paths meet with ESP apart, and the merges
     * that can't be evened out; null if paths never meet apart.
     */
    fun plan(): Plan? {
        walk()
        if (conflict == null) return null
        repeat(MAX_ROUNDS) {
            val at = conflict ?: return planned()
            val into = incoming.getValue(at)
            val target = into.values.max()
            val seen = mutableSetOf<Address>()
            val saved = pops.toMap()
            val savedJoins = joins.mapValues { it.value.toSet() }
            if (!into.all { (from, depth) ->
                    depth == target || popAt(from, (target - depth).toInt(), depth, at, seen)
                }
            ) {
                stuck[at] = into.toMap()
                pops.clear()
                pops.putAll(saved)
                joins.clear()
                savedJoins.forEach { (call, merges) -> joins[call] = merges.toMutableSet() }
            }
            walk()
        }
        return planned()
    }

    private fun planned() = Plan(pops.mapValues { (call, extra) -> Pop(extra, joins[call].orEmpty()) }, stuck.toMap())

    /**
     * Make the path out of block [from] pop [extra] more, at the last call before it whose own
     * arguments are what is still pushed — the call at which ESP stood at [deep]. A call that pushes
     * and pops its own arguments in between is passed over: the bytes predate it. [join] is the merge
     * this evens out.
     */
    private fun popAt(from: Address, extra: Int, deep: Long, join: Address, seen: MutableSet<Address>): Boolean {
        if (!seen.add(from)) return true
        val block = blocks.getCodeBlockAt(from, TaskMonitor.DUMMY) ?: return false
        val culprit = program.listing.getInstructions(block, true).toList().lastOrNull {
            depthAtCall[it.address]?.plus(4) == deep
        }
        if (culprit != null) {
            if (culprit.flows.size != 1 || program.functionManager.getFunctionAt(culprit.flows.single()) == null) {
                return false
            }
            pops.merge(culprit.address, extra, Int::plus)
            joins.getOrPut(culprit.address) { mutableSetOf() } += join
            return true
        }
        val preds = block.sources().filter { (flow, start) -> !flow.isCall && f.body.contains(start) }
        return preds.isNotEmpty() && preds.all { (_, start) -> popAt(start, extra, deep, join, seen) }
    }

    private fun walk() {
        entry = mutableMapOf()
        depthAtCall = mutableMapOf()
        incoming = mutableMapOf()
        conflict = null
        val work = ArrayDeque<Triple<Address, Map<Varnode, Long>, Address?>>()
        work.add(Triple(f.entryPoint, mapOf(esp to 0L), null))
        while (work.isNotEmpty()) {
            val (at, state, from) = work.removeFirst()
            if (!f.body.contains(at)) continue
            val sp = state[esp] ?: continue
            val into = incoming.getOrPut(at) { sortedMapOf() }
            if (from != null) into[from] = sp
            entry[at]?.let { seen ->
                if (seen != sp && isNewConflict(at)) conflict = at
                continue
            }
            entry[at] = sp
            val block = blocks.getCodeBlockAt(at, TaskMonitor.DUMMY) ?: continue
            val out = run(block, state) ?: continue
            block.destinations().filterNot {
                it.first.isCall
            }.forEach { work.add(Triple(it.second, out, block.firstStartAddress)) }
        }
    }

    /** Whether a merge of two ESPs at [at] is the one to fix next: the first, not given up on, read past. */
    private fun isNewConflict(at: Address) = conflict == null && at !in stuck && readsEsp(at)

    /** [state] after [block], or null where the path ends there. */
    private fun run(block: CodeBlock, state: Map<Varnode, Long>): Map<Varnode, Long>? = state.toMutableMap().apply {
        for (insn in program.listing.getInstructions(block, true)) {
            for (op in insn.pcode) if (!step(insn, op)) return null
        }
    }

    private fun MutableMap<Varnode, Long>.step(insn: Instruction, op: PcodeOp): Boolean {
        fun value(v: Varnode) = if (v.isConstant) null else get(v)
        fun set(v: Long?) = op.output?.let { if (v == null) remove(it) else put(it, v) }
        when (op.opcode) {
            PcodeOp.CALL, PcodeOp.CALLIND -> {
                val purge = overridden[insn.address] ?: op.calleePurge() ?: return false
                get(esp)?.let {
                    depthAtCall.putIfAbsent(insn.address, it)
                    put(esp, it + 4 + purge + (pops[insn.address] ?: 0))
                }
            }

            PcodeOp.RETURN -> return false

            PcodeOp.COPY, PcodeOp.INT_AND -> set(value(op.getInput(0)))

            PcodeOp.INT_ADD, PcodeOp.INT_SUB -> {
                val x = value(op.getInput(0))
                val k = op.getInput(1).takeIf { it.isConstant }?.offset?.toInt()?.toLong()
                set(
                    when {
                        x == null || k == null -> null
                        op.opcode == PcodeOp.INT_ADD -> x + k
                        else -> x - k
                    },
                )
            }

            else -> set(null)
        }
        return true
    }

    /** What a direct call's callee pops beyond its return address; null if it never returns, 0 if unknown. */
    private fun PcodeOp.calleePurge(): Int? = when (opcode) {
        PcodeOp.CALL -> program.functionManager.getFunctionAt(getInput(0).address)?.let { return it.purgeOf() } ?: 0
        else -> 0
    }

    /** The bytes [callee] pops beyond its return address, or null if it never returns. */
    private fun Function.purgeOf(): Int? = (if (isThunk) getThunkedFunction(true) else this).run {
        if (hasNoReturn()) return null
        stackPurgeSize.takeUnless {
            it == Function.UNKNOWN_STACK_DEPTH_CHANGE || it == Function.INVALID_STACK_DEPTH_CHANGE
        } ?: 0
    }

    /**
     * Whether code from [at] reads ESP before setting it from something else. A merge that runs
     * straight into `lea -0xc(%ebp),%esp` or `leave` is harmless: nothing sees which ESP arrived.
     */
    private fun readsEsp(at: Address): Boolean {
        val derived = mutableSetOf<Varnode>()
        var cur: Address? = at
        repeat(READ_LOOKAHEAD) {
            val insn = program.listing.getInstructionAt(cur ?: return true) ?: return true
            for (op in insn.pcode) {
                val usesSp = op.inputs.any { it == esp || it in derived }
                val out = op.output
                when {
                    !usesSp -> if (out == esp) return false
                    out == null || !out.isUnique -> return true
                    else -> derived += out
                }
            }
            val flow = insn.flowType
            cur = when {
                flow.isTerminal -> return false
                flow.isCall -> return true
                flow.isJump && flow.isUnConditional -> insn.flows.singleOrNull() ?: return true
                else -> insn.fallThrough
            }
        }
        return true
    }

    private fun CodeBlock.destinations() = getDestinations(TaskMonitor.DUMMY).let { i ->
        generateSequence { if (i.hasNext()) i.next() else null }.map { it.flowType to it.destinationAddress }.toList()
    }

    private fun CodeBlock.sources() = getSources(TaskMonitor.DUMMY).let { i ->
        generateSequence { if (i.hasNext()) i.next() else null }
            .map { it.flowType to it.sourceBlock.firstStartAddress }.toList()
    }

    companion object {
        const val MAX_ROUNDS = 32
        const val READ_LOOKAHEAD = 64
    }
}
