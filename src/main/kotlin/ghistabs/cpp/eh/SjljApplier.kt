package ghistabs.cpp.eh

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.program.database.function.OverlappingFunctionException
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.DuplicateNameException
import ghidra.util.exception.InvalidInputException
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.frameBias
import ghistabs.minus
import ghistabs.overlaps
import ghistabs.withLength
import kotlin.math.abs

/**
 * Applies gcc's SJLJ exception ABI ([SjljAbi]) to the functions that register with it, everything
 * but laying their LSDAs, which [SjljLsdaApplier] does:
 * - the receiver each stores into `jbuf[1]`, where the unwinder `longjmp`s, disassembled into the
 *   function with its landing pads and labelled [RESUME_LABEL] ([layReceiver]);
 * - the `SjLj_Function_Context` each keeps on its stack, typed as a local [LOCAL] with the
 *   `__builtin_setjmp` buffer gcc's stabs leave out ([typeContexts]);
 * - what each `fc.call_site` store selects in the LSDA, as a comment ([commentCallSites]);
 * - the libgcc and libsupc++ entry points the unwinding goes through, the `_Unwind_SjLj_*` calls, the
 *   personality routines and the `__cxa_*` throw and catch calls, wherever nothing more definite than
 *   analysis has typed them ([typeEntryPoints]).
 */
class SjljApplier(val program: Program, private val monitor: TaskMonitor, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val listing = program.listing
    private val fm = program.functionManager

    /**
     * Apply all of it to the registrations whose store [set] holds, and to the entry points it holds;
     * returns how many contexts and entry points were typed.
     */
    fun applyAll(set: AddressSetView): Pair<Int, Int> {
        val stored = program.sjljLsdas(program.memory, monitor)
        val all = stored.values.flatMap { it.registrations }
        if (all.isEmpty()) return 0 to 0
        val regs = all.filter { set.contains(it.store) }
        // Again after the import, which can recreate a function and with it drop the labels in it.
        regs.forEach { layReceiver(it) }
        regs.forEach { reg -> stored[reg.lsda]?.lsda?.let { commentCallSites(reg, it) } }
        val abi = SjljAbi(program.dataTypeManager)
        return typeContexts(regs, abi) to typeEntryPoints(all, abi) { set.contains(it) }
    }

    // The receiver

    /**
     * Disassemble [reg]'s receiver, with the code it flows to, into its function's body, and label it
     * [RESUME_LABEL]`_<address>`: the unwinder `longjmp`s to it, so no flow from the entry reaches it,
     * nor the landing pads it dispatches to.
     */
    fun layReceiver(reg: Registration) {
        val at = reg.resume ?: return
        val fn = fm.getFunctionContaining(reg.store) ?: return
        if (fm.getFunctionAt(at) != null || !program.memory.executeSet.contains(at)) return
        if (listing.getInstructionAt(at) == null) {
            if (listing.getDefinedDataContaining(at) != null || listing.getInstructionContaining(at) != null) {
                warn("sjlj-resume-occupied", "receiver of ${fn.name} is inside other code or data", at)
                return
            }
            DisassembleCommand(at, null, true).applyTo(program, monitor)
            listing.getInstructionAt(at) ?: return warn("sjlj-resume-undecoded", "receiver of ${fn.name}", at)
        }
        referenceReceiver(fn, reg, at)
        // Within the function's extent: gcc puts the receiver and its landing pads there, and a flow
        // past it may be a function nothing has defined yet, which the stabs import would then find taken.
        val flow = CreateFunctionCmd.getFunctionBody(program, at, monitor)
            .intersect(AddressSet(fn.entryPoint, fn.body.maxAddress))
        if (!fn.body.contains(flow)) {
            try {
                fn.body = fn.body.union(flow)
            } catch (e: OverlappingFunctionException) {
                warn("sjlj-resume-overlap", "receiver of ${fn.name} runs into another function: $e", at)
            }
        }
        // Global, as the LSDA header's is: the decompiler names no label in a function's namespace,
        // and with this one `fc.jbuf.resume = &sjlj_dispatch_<address>`.
        val symtab = program.symbolTable
        val name = "${RESUME_LABEL}_$at"
        if (symtab.getSymbols(at).none { it.name == name }) {
            symtab.createLabel(at, name, SourceType.ANALYSIS).setPrimary()
        }
        listing.setComment(at, CommentType.PRE, RECEIVER_COMMENT)
    }

    /**
     * A flow reference to the receiver [at] from the instruction in [fn] that takes its address, the
     * nearest to [reg]'s store: the edge the unwinder's `longjmp` takes, which no instruction spells.
     * Ghidra keeps code a flow reference reaches through a no-return repair, which otherwise clears
     * the receiver and its landing pads as dead code past a call, and takes it into the body each
     * time it recomputes one. Not a branch in the instruction's p-code, so the decompiler, which
     * follows that, still sees the address taken and nothing more.
     */
    private fun referenceReceiver(fn: Function, reg: Registration, at: Address) {
        val (insn, op) = listing.getInstructions(fn.body, true).iterator().asSequence()
            .flatMap { insn -> (0..<insn.numOperands).map { insn to it } }
            .filter { (insn, op) -> insn.getScalar(op)?.unsignedValue == at.offset }
            .minByOrNull { (insn, _) -> abs(insn.address - reg.store) }
            ?: return
        val refs = program.referenceManager
        if (refs.getReferencesFrom(insn.address, op).none { it.toAddress == at && it.referenceType.isFlow }) {
            refs.addMemoryReference(insn.address, at, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, op)
        }
    }

    // The call sites

    /**
     * What each call site [reg]'s function stores into `fc.call_site` selects in [lsda], as Ghidra's
     * `GCC Exception Handlers` analyzer comments the try and catch ranges of a DWARF function. SJLJ
     * has no ranges: before each call that may throw, gcc stores the index of the call-site record
     * that covers it, so each store gets a pre comment naming its landing pad and what that does:
     * ```
     * SJLJ call site 2, landing pad 1: catch (CryptoPP::InvalidArgument), cleanup
     * ```
     * and the receiver, which dispatches on the landing pad index, one line per pad. The decompiler
     * shows pre comments, so each lands above the protected call's `fc.call_site = 2;`.
     */
    fun commentCallSites(reg: Registration, lsda: SjljLsda) {
        val fn = fm.getFunctionContaining(reg.store) ?: return
        val slot = reg.lsdaDisplacement - SjljAbi.LSDA_OFFSET + SjljAbi.CALL_SITE_OFFSET
        for (insn in listing.getInstructions(fn.body, true)) {
            monitor.checkCancelled()
            val text = insn.storedImmediate(slot)?.let { callSiteComment(lsda, it) } ?: continue
            val existing = listing.getComment(CommentType.PRE, insn.address)
            if (existing == null || existing.startsWith(CALL_SITE_PREFIX)) {
                listing.setComment(insn.address, CommentType.PRE, text)
            }
        }
        reg.resume?.let { commentLandingPads(it, lsda) }
    }

    /**
     * What call-site [index] selects, as `__gxx_personality_sj0` reads it: below 0 no handler
     * (nothing to say), 0 terminate, N the Nth record.
     */
    private fun callSiteComment(lsda: SjljLsda, index: Long): String? = when {
        index < 0 -> null

        index == 0L -> "$CALL_SITE_PREFIX 0: terminate if anything throws"

        else -> lsda.callSites.getOrNull((index - 1).toInt())?.let {
            "$CALL_SITE_PREFIX $index, landing pad ${it.landingPad}: ${lsda.handlers(it, program)}"
        }
    }

    /** One line per landing pad of [lsda] under [receiver]'s own comment, [layReceiver]'s. */
    private fun commentLandingPads(receiver: Address, lsda: SjljLsda) {
        val head = listing.getComment(CommentType.PRE, receiver)?.lineSequence()?.first() ?: return
        val pads = lsda.callSites.groupBy { it.landingPad }.toSortedMap().map { (pad, sites) ->
            "landing pad $pad: " + sites.map { lsda.handlers(it, program) }.distinct().joinToString(" | ")
        }
        listing.setComment(receiver, CommentType.PRE, (listOf(head) + pads).joinToString("\n"))
    }

    // The context

    /**
     * Commit an [LOCAL] local over each registering function's context, the LSDA slot being
     * [SjljAbi.LSDA_OFFSET] into it, unless one an import or a user made covers it; returns how many.
     */
    fun typeContexts(regs: List<Registration>, abi: SjljAbi): Int {
        val dt = abi.functionContext ?: run {
            warn("sjlj-context-layout", "${SjljAbi.CONTEXT} is not gcc's, so no context is typed", null)
            return 0
        }
        var typed = 0
        for (reg in regs.distinctBy { it.store }) {
            monitor.checkCancelled()
            val fn = fm.getFunctionContaining(reg.store) ?: continue
            val offset = reg.lsdaDisplacement.toInt() - SjljAbi.LSDA_OFFSET - fn.frameBias(monitor)
            if (commitContext(fn, offset, dt)) typed += 1
        }
        return typed
    }

    private fun commitContext(fn: Function, offset: Int, dt: Structure): Boolean {
        val frame = fn.stackFrame
        val span = offset.withLength(dt.length)
        val overlapping = frame.stackVariables.filter { it.stackOffset.withLength(it.length).overlaps(span) }
        if (overlapping.any { it.isContext(dt, offset) }) return false
        if (overlapping.any { it.source == SourceType.IMPORTED || it.source == SourceType.USER_DEFINED }) {
            debug("sjlj-context-taken", "a defined local covers ${fn.name}'s context", fn.entryPoint)
            return false
        }
        overlapping.forEach { fn.removeVariable(it) }
        val name = generateSequence(LOCAL) { "${it}_" }.first { n -> fn.allVariables.none { it.name == n } }
        return try {
            frame.createVariable(name, offset, dt, SourceType.ANALYSIS)
            true
        } catch (e: InvalidInputException) {
            warn("sjlj-context-error", "${fn.name}: $e", fn.entryPoint)
            false
        } catch (e: DuplicateNameException) {
            warn("sjlj-context-error", "${fn.name}: $e", fn.entryPoint)
            false
        }
    }

    private fun Variable.isContext(dt: DataType, offset: Int) = stackOffset == offset && dataType.isEquivalent(dt)

    // The entry points

    /**
     * Give each gcc EH entry point its [SjljAbi.signature], by name with or without the PE underscore,
     * where its signature is no more than analysis' and [covers] holds its entry; returns how many. A
     * stripped binary names neither its personality routine nor `_Unwind_SjLj_Register`, but [regs]
     * give both: what they store, and what each calls first after its stores.
     */
    fun typeEntryPoints(regs: List<Registration>, abi: SjljAbi, covers: (Address) -> Boolean = { true }): Int {
        val byName = mutableMapOf<Function, String>()
        for (fn in fm.getFunctions(true).iterator().asSequence() + fm.externalFunctions.iterator().asSequence()) {
            monitor.checkCancelled()
            byName[fn] = fn.name.takeIf { abi.signature(it) != null }
                ?: fn.name.removePrefix("_").takeIf { abi.signature(it) != null }
                ?: continue
        }
        fun unnamed(fn: Function?, name: String) {
            if (fn != null && fn !in byName && fn.symbol.source == SourceType.DEFAULT) byName[fn] = name
        }
        regs.map { it.personality }.distinct().forEach { unnamed(fm.getFunctionAt(it), SjljAbi.PERSONALITY) }
        registerCallee(regs)?.let { unnamed(fm.getFunctionAt(it), SjljAbi.REGISTER) }

        var typed = 0
        for ((fn, name) in byName) {
            monitor.checkCancelled()
            if (!covers(fn.entryPoint)) continue
            val sig = abi.signature(name) ?: continue
            if (typeEntryPoint(fn, name, sig)) typed += 1
        }
        return typed
    }

    /** What most of [regs] call first after their stores: `_Unwind_SjLj_Register(&fc)`. */
    private fun registerCallee(regs: List<Registration>) = regs
        .mapNotNull { reg ->
            listing.getInstructions(reg.store, true).iterator().asSequence()
                .take(REGISTER_SCAN)
                .firstOrNull { it.flowType.isCall }
                ?.flows?.singleOrNull()
        }
        .groupingBy { it }.eachCount()
        .maxByOrNull { it.value }
        ?.takeIf { it.value * 2 > regs.size }
        ?.key

    private fun typeEntryPoint(fn: Function, name: String, sig: SjljAbi.Signature): Boolean {
        // No stab says a function never returns, so that is the ABI's even where they give the rest.
        if (sig.noReturn && !fn.hasNoReturn()) fn.setNoReturn(true)
        if (fn.signatureSource == SourceType.IMPORTED || fn.signatureSource == SourceType.USER_DEFINED) return false
        if (fn.has(sig)) return false
        return try {
            if (fn.symbol.source == SourceType.DEFAULT) fn.setName(name, SourceType.ANALYSIS)
            fn.updateFunction(
                "__cdecl",
                ReturnParameterImpl(sig.ret, program),
                sig.params.map { (n, t) -> ParameterImpl(n, t, program) },
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true,
                SourceType.ANALYSIS,
            )
            if (sig.noReturn) fn.setNoReturn(true)
            true
        } catch (e: InvalidInputException) {
            warn("sjlj-signature-error", "$name: $e", fn.entryPoint)
            false
        } catch (e: DuplicateNameException) {
            warn("sjlj-signature-error", "$name: $e", fn.entryPoint)
            false
        }
    }

    /** Whether this is already [sig], as an earlier run left it. */
    private fun Function.has(sig: SjljAbi.Signature) = signatureSource == SourceType.ANALYSIS &&
        callingConventionName == "__cdecl" && returnType.isEquivalent(sig.ret) &&
        parameters.size == sig.params.size &&
        parameters.zip(sig.params).all { (p, s) -> p.name == s.first && p.dataType.isEquivalent(s.second) }

    companion object {
        /** The receiver's label, `sjlj_dispatch_<address>`. */
        const val RESUME_LABEL = "sjlj_dispatch"

        /** The context's local. */
        const val LOCAL = "fc"

        /** How each call-site comment starts, so a later run replaces its own and no one else's. */
        const val CALL_SITE_PREFIX = "SJLJ call site"

        private const val RECEIVER_COMMENT =
            "SJLJ receiver (jbuf[1]): the unwinder longjmps here to dispatch on call_site to a landing pad"

        /** How far past the LSDA store `call _Unwind_SjLj_Register` may be, in instructions. */
        private const val REGISTER_SCAN = 16
    }
}

/** The immediate this `movl $immediate, displacement(%ebp)` stores, if it is one to [displacement]. */
private fun Instruction.storedImmediate(displacement: Long): Long? {
    if (mnemonicString != "MOV" || numOperands != 2) return null
    val dest = getOpObjects(0)
    if (dest.none { it is Register && it.name == "EBP" }) return null
    if (dest.filterIsInstance<Scalar>().singleOrNull()?.signedValue != displacement) return null
    return getScalar(1)?.signedValue
}
