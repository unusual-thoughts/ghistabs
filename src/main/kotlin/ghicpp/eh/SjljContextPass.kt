package ghicpp.eh

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
import ghistabs.cancelOnly
import ghistabs.diagnose.DiagnosticSink
import ghistabs.frameBias
import ghistabs.minus
import ghistabs.overlaps
import ghistabs.withLength
import kotlin.math.abs

/**
 * Applies [SjljTypes] to the functions that register with it ([SjljLsdaPass] lays the LSDAs and receivers,
 * and again here, as the import can recreate a function and drop the labels in it):
 * - types the stack context as local [LOCAL] ([typeContexts]);
 * - comments what each `fc.call_site` store selects ([commentCallSites]);
 * - types the `_Unwind_SjLj_*`, personality and `__cxa_*` entry points ([typeEntryPoints]).
 */
class SjljContextPass(val program: Program, private val sink: DiagnosticSink) : DiagnosticSink by sink {
    private val listing = program.listing
    private val fm = program.functionManager

    /** Applies everything to the registrations and entry points in [set]; returns contexts and entry points typed. */
    fun run(set: AddressSetView, monitor: TaskMonitor): Pair<Int, Int> {
        val stored = SjljRegistrationFinder(program).lsdas(program.memory, monitor)
        val all = stored.values.flatMap { it.registrations }
        if (all.isEmpty()) return 0 to 0
        val regs = all.filter { set.contains(it.store) }
        // Again after the import, which can recreate a function and with it drop the labels in it.
        val receivers = SjljLsdaPass(program, sink)
        monitor.initialize(regs.size.toLong(), "Laying SJLJ receivers")
        for (reg in regs) {
            monitor.increment()
            receivers.layReceiver(reg, monitor.cancelOnly)
        }
        monitor.initialize(regs.size.toLong(), "Commenting SJLJ call sites")
        for (reg in regs) {
            monitor.increment()
            stored[reg.lsda]?.lsda?.let { reg.commentCallSites(it, monitor) }
        }
        val types = SjljTypes(program.dataTypeManager)
        return typeContexts(regs, types, monitor) to typeEntryPoints(all, types, monitor) { set.contains(it) }
    }

    /**
     * Pre-comments each `fc.call_site` store with the call-site record it selects in [lsda], and the
     * receiver with one line per landing pad, the SJLJ counterpart of Ghidra's DWARF try/catch comments:
     * ```
     * SJLJ call site 2, landing pad 1: catch (std::bad_alloc), cleanup
     * ```
     */
    fun SjljRegistration.commentCallSites(lsda: SjljLsda, monitor: TaskMonitor) {
        val fn = fm.getFunctionContaining(store) ?: return
        val slot = lsdaDisplacement - SjljTypes.LSDA_OFFSET + SjljTypes.CALL_SITE_OFFSET
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
    fun typeContexts(regs: List<SjljRegistration>, types: SjljTypes, monitor: TaskMonitor): Int {
        val dt = types.functionContext ?: run {
            warn("sjlj-context-layout", "${SjljTypes.CONTEXT} is not gcc's, so no context is typed", null)
            return 0
        }
        var typed = 0
        val stores = regs.distinctBy { it.store }
        monitor.initialize(stores.size.toLong(), "Typing SJLJ function contexts")
        for (reg in stores) {
            monitor.increment()
            val fn = fm.getFunctionContaining(reg.store) ?: continue
            val offset = reg.lsdaDisplacement.toInt() - SjljTypes.LSDA_OFFSET - fn.frameBias(monitor)
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
     * Gives each gcc EH entry point in [covers] its [SjljTypes.signature] unless something firmer than
     * analysis typed it; returns how many. In a stripped binary the personality routine and
     * `_Unwind_SjLj_Register` are found from [regs] instead of by name.
     */
    fun typeEntryPoints(
        regs: List<SjljRegistration>,
        types: SjljTypes,
        monitor: TaskMonitor,
        covers: (Address) -> Boolean = { true },
    ): Int {
        val byName = mutableMapOf<Function, String>()
        monitor.initialize(fm.functionCount.toLong(), "Finding gcc EH entry points")
        for (fn in fm.getFunctions(true).iterator().asSequence() + fm.externalFunctions.iterator().asSequence()) {
            monitor.increment()
            byName[fn] = fn.name.takeIf { types.signature(it) != null }
                ?: fn.name.removePrefix("_").takeIf { types.signature(it) != null }
                ?: continue
        }
        fun unnamed(fn: Function?, name: String) {
            if (fn != null && fn !in byName && fn.symbol.source == SourceType.DEFAULT) byName[fn] = name
        }
        regs.map { it.personality }.distinct().forEach { unnamed(fm.getFunctionAt(it), SjljTypes.PERSONALITY) }
        registerCallee(regs)?.let { unnamed(fm.getFunctionAt(it), SjljTypes.REGISTER) }

        var typed = 0
        monitor.initialize(byName.size.toLong(), "Typing gcc EH entry points")
        for ((fn, name) in byName) {
            monitor.increment()
            if (!covers(fn.entryPoint)) continue
            val sig = types.signature(name) ?: continue
            if (fn.typeEntryPoint(name, sig)) typed += 1
        }
        return typed
    }

    /** What most of [regs] call first after their stores: `_Unwind_SjLj_Register(&fc)`. */
    private fun registerCallee(regs: List<SjljRegistration>) = regs
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

    private fun Function.typeEntryPoint(name: String, sig: SjljTypes.Signature): Boolean {
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
    private fun Function.has(sig: SjljTypes.Signature) = signatureSource == SourceType.ANALYSIS &&
        callingConventionName == "__cdecl" && returnType.isEquivalent(sig.ret) &&
        parameters.size == sig.params.size &&
        parameters.zip(sig.params).all { (p, s) -> p.name == s.first && p.dataType.isEquivalent(s.second) }

    companion object {
        /** The context's local. */
        const val LOCAL = "fc"

        /** How each call-site comment starts, so a later run replaces its own and no one else's. */
        const val CALL_SITE_PREFIX = "SJLJ call site"

        /** How far past the LSDA store `call _Unwind_SjLj_Register` may be, in instructions. */
        private const val REGISTER_SCAN = 16
    }
}
