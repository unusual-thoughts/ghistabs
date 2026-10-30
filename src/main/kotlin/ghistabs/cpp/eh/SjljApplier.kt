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
 * Applies [SjljAbi] to the functions that register with it ([SjljLsdaApplier] lays the LSDAs):
 * - disassembles and labels the receiver the unwinder `longjmp`s to ([layReceiver]);
 * - types the stack context as local [LOCAL] ([typeContexts]);
 * - comments what each `fc.call_site` store selects ([commentCallSites]);
 * - types the `_Unwind_SjLj_*`, personality and `__cxa_*` entry points ([typeEntryPoints]).
 */
class SjljApplier(val program: Program, private val monitor: TaskMonitor, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val listing = program.listing
    private val fm = program.functionManager
    private val refs = program.referenceManager

    /** Applies everything to the registrations and entry points in [set]; returns contexts and entry points typed. */
    fun applyAll(set: AddressSetView): Pair<Int, Int> {
        val stored = program.sjljLsdas(program.memory, monitor)
        val all = stored.values.flatMap { it.registrations }
        if (all.isEmpty()) return 0 to 0
        val regs = all.filter { set.contains(it.store) }
        // Again after the import, which can recreate a function and with it drop the labels in it.
        regs.forEach { layReceiver(it) }
        regs.forEach { reg -> stored[reg.lsda]?.lsda?.let { reg.commentCallSites(it) } }
        val abi = SjljAbi(program.dataTypeManager)
        return typeContexts(regs, abi) to typeEntryPoints(all, abi) { set.contains(it) }
    }

    /**
     * Disassembles [reg]'s receiver and the landing pads it reaches into its function, labelled
     * [RESUME_LABEL]`_<address>`. Only the unwinder's `longjmp` reaches them, so no flow does.
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
        reg.referenceReceiver(fn, at)
        // Within the function's extent: gcc puts the receiver and its landing pads there, and a flow
        // past it may be a function nothing has defined yet, which the stabs import would then find taken.
        // The extent runs to the receiver's last instruction, the `call _Unwind_SjLj_Resume` it falls
        // through to: when the try block's code ends in a jump back, gcc lays the pads and the receiver
        // past the last instruction the entry reaches, and Ghidra's body stops there.
        var last = listing.getInstructionAt(at)
        while (last.hasFallthrough()) last = listing.getInstructionAt(last.fallThrough) ?: break
        val flow = CreateFunctionCmd.getFunctionBody(program, at, monitor)
            .intersect(AddressSet(fn.entryPoint, maxOf(fn.body.maxAddress, last.maxAddress)))
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
     * Adds a flow reference to the receiver [at] from the instruction in [fn] nearest the store that
     * takes its address, standing in for the `longjmp` edge. It keeps a no-return repair from clearing
     * the receiver as dead code, and keeps it in the body when Ghidra recomputes one. The p-code is
     * unchanged, so the decompiler is unaffected.
     */
    private fun Registration.referenceReceiver(fn: Function, at: Address) {
        val (insn, op) = listing.getInstructions(fn.body, true).iterator().asSequence()
            .flatMap { insn -> (0..<insn.numOperands).map { insn to it } }
            .filter { (insn, op) -> insn.getScalar(op)?.unsignedValue == at.offset }
            .minByOrNull { (insn, _) -> abs(insn.address - store) }
            ?: return
        if (refs.getReferencesFrom(insn.address, op).none { it.toAddress == at && it.referenceType.isFlow }) {
            refs.addMemoryReference(insn.address, at, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, op)
        }
    }

    /**
     * Pre-comments each `fc.call_site` store with the call-site record it selects in [lsda], and the
     * receiver with one line per landing pad, the SJLJ counterpart of Ghidra's DWARF try/catch comments:
     * ```
     * SJLJ call site 2, landing pad 1: catch (std::bad_alloc), cleanup
     * ```
     */
    fun Registration.commentCallSites(lsda: SjljLsda) {
        val fn = fm.getFunctionContaining(store) ?: return
        val slot = lsdaDisplacement - SjljAbi.LSDA_OFFSET + SjljAbi.CALL_SITE_OFFSET
        for (insn in listing.getInstructions(fn.body, true)) {
            monitor.checkCancelled()
            val text = insn.storedImmediate(slot)?.let { callSiteComment(lsda, it) } ?: continue
            val existing = listing.getComment(CommentType.PRE, insn.address)
            if (existing == null || existing.startsWith(CALL_SITE_PREFIX)) {
                listing.setComment(insn.address, CommentType.PRE, text)
            }
        }
        resume?.let { commentLandingPads(it, lsda) }
    }

    /** The immediate this `movl $immediate, displacement(%ebp)` stores, if it is one to [displacement]. */
    private fun Instruction.storedImmediate(displacement: Long): Long? {
        if (mnemonicString != "MOV" || numOperands != 2) return null
        val dest = getOpObjects(0)
        if (dest.none { it is Register && it.name == "EBP" }) return null
        if (dest.filterIsInstance<Scalar>().singleOrNull()?.signedValue != displacement) return null
        return getScalar(1)?.signedValue
    }

    /** What call-site [index] selects: below 0 nothing (null), 0 terminate, N the Nth record. */
    private fun callSiteComment(lsda: SjljLsda, index: Long): String? = when {
        index < 0 -> null

        index == 0L -> "$CALL_SITE_PREFIX 0: terminate if anything throws"

        else -> lsda.callSites.getOrNull((index - 1).toInt())?.let {
            "$CALL_SITE_PREFIX $index, landing pad ${it.landingPad}: ${lsda.handlers(it, program)}"
        }
    }

    /** Appends one line per landing pad of [lsda] to [receiver]'s comment. */
    private fun commentLandingPads(receiver: Address, lsda: SjljLsda) {
        val head = listing.getComment(CommentType.PRE, receiver)?.lineSequence()?.first() ?: return
        val pads = lsda.callSites.groupBy { it.landingPad }.toSortedMap().map { (pad, sites) ->
            "landing pad $pad: " + sites.map { lsda.handlers(it, program) }.distinct().joinToString(" | ")
        }
        listing.setComment(receiver, CommentType.PRE, (listOf(head) + pads).joinToString("\n"))
    }

    /**
     * Commits local [LOCAL] over each function's context, found from its LSDA slot, unless an import or
     * a user already typed it; returns how many.
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
            if (fn.commitContext(offset, dt)) typed += 1
        }
        return typed
    }

    private fun Function.commitContext(offset: Int, dt: Structure): Boolean {
        val span = offset.withLength(dt.length)
        val overlapping = stackFrame.stackVariables.filter { it.stackOffset.withLength(it.length).overlaps(span) }
        if (overlapping.any { it.isContext(dt, offset) }) return false
        if (overlapping.any { it.source == SourceType.IMPORTED || it.source == SourceType.USER_DEFINED }) {
            debug("sjlj-context-taken", "a defined local covers $name's context", entryPoint)
            return false
        }
        overlapping.forEach { removeVariable(it) }
        val name = generateSequence(LOCAL) { "${it}_" }.first { n -> allVariables.none { it.name == n } }
        return try {
            stackFrame.createVariable(name, offset, dt, SourceType.ANALYSIS)
            true
        } catch (e: InvalidInputException) {
            warn("sjlj-context-error", "$name: $e", entryPoint)
            false
        } catch (e: DuplicateNameException) {
            warn("sjlj-context-error", "$name: $e", entryPoint)
            false
        }
    }

    private fun Variable.isContext(dt: DataType, offset: Int) = stackOffset == offset && dataType.isEquivalent(dt)

    /**
     * Gives each gcc EH entry point in [covers] its [SjljAbi.signature] unless something firmer than
     * analysis typed it; returns how many. In a stripped binary the personality routine and
     * `_Unwind_SjLj_Register` are found from [regs] instead of by name.
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
            if (fn.typeEntryPoint(name, sig)) typed += 1
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

    private fun Function.typeEntryPoint(name: String, sig: SjljAbi.Signature): Boolean {
        // No stab says a function never returns, so that is the ABI's even where they give the rest.
        if (sig.noReturn && !hasNoReturn()) setNoReturn(true)
        if (signatureSource == SourceType.IMPORTED || signatureSource == SourceType.USER_DEFINED) return false
        if (has(sig)) return false
        return try {
            if (symbol.source == SourceType.DEFAULT) setName(name, SourceType.ANALYSIS)
            updateFunction(
                "__cdecl",
                ReturnParameterImpl(sig.ret, program),
                sig.params.map { (n, t) -> ParameterImpl(n, t, program) },
                FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                true,
                SourceType.ANALYSIS,
            )
            if (sig.noReturn) setNoReturn(true)
            true
        } catch (e: InvalidInputException) {
            warn("sjlj-signature-error", "$name: $e", entryPoint)
            false
        } catch (e: DuplicateNameException) {
            warn("sjlj-signature-error", "$name: $e", entryPoint)
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
