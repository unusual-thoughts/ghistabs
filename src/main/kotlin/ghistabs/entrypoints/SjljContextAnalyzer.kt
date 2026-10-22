package ghistabs.entrypoints

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.SourceType
import ghidra.util.exception.DuplicateNameException
import ghidra.util.exception.InvalidInputException
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.MessageLogSink
import ghistabs.eh.SjljAbi
import ghistabs.frameBias

/**
 * Types gcc's SJLJ exception ABI ([SjljAbi]) where a program uses it: the `SjLj_Function_Context` each
 * registering function keeps on its stack, as a local `fc`, with the `__builtin_setjmp` buffer gcc's
 * stabs leave out; and the libgcc and libsupc++ entry points the unwinding goes through, the
 * `_Unwind_SjLj_*` calls, the personality routines and the `__cxa_*` throw and catch calls, wherever
 * nothing more definite than analysis has typed them.
 *
 * The registrations are [SjljLsdaAnalyzer]'s, which runs before the Stabs Importer and labels and
 * disassembles each function's receiver. The import runs this again once it has applied its symbols
 * ([typeAll]), so a type the stabs on libgcc define is the one used, and a signature they give is
 * left as it is, whichever order the two run in.
 */
class SjljContextAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Type the SJLJ function context gcc functions with exception handling keep, and the libgcc and " +
            "libsupc++ exception entry points.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority.LOW_PRIORITY.after()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program) = SjljLsdaAnalyzer().canAnalyze(program)

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        // Stabs still to import type libgcc themselves, and the import runs this after them.
        if (StabsAnalyzer().canAnalyze(program)) return true
        // Byte analyzers run again on whatever code a later analyzer changes (call fixups re-add theirs),
        // so only what [set] covers: the whole program once, then just the changed code.
        val (contexts, signatures) = typeAll(program, monitor, MessageLogSink(log, originator = NAME), set)
        if (contexts + signatures > 0) log.appendMsg(NAME, "typed $contexts context(s), $signatures entry point(s)")
        return true
    }

    companion object {
        const val NAME = "GCC SJLJ unwind context"
        const val LOCAL = "fc"

        /** Whether the analyzer is on in [program]'s analysis options, which the stabs import honours too. */
        fun isEnabled(program: Program) = program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean(NAME, true)

        /**
         * Type the context of every registering function whose store [set] holds, and the entry points it
         * holds, all of them where it is null; returns how many of each.
         */
        fun typeAll(
            program: Program,
            monitor: TaskMonitor,
            sink: DiagnosticSink,
            set: AddressSetView? = null,
        ): Pair<Int, Int> {
            if (!SjljLsdaAnalyzer().canAnalyze(program)) return 0 to 0
            val found = SjljLsdaAnalyzer.lsdas(program, program.memory, monitor)
            val all = found.values.flatMap { it.second }
            if (all.isEmpty()) return 0 to 0
            val regs = all.filter { set == null || set.contains(it.store) }
            // Again after the import, which can recreate a function and with it drop the labels in it.
            regs.forEach { SjljLsdaAnalyzer.layResume(program, it, monitor, sink) }
            for (reg in regs) {
                found[reg.lsda]?.first?.let { SjljHandlerComments.comment(program, reg, it, monitor) }
            }
            val abi = SjljAbi(program.dataTypeManager)
            val contexts = typeContexts(program, regs, abi, monitor, sink)
            return contexts to typeEntryPoints(program, all, abi, monitor, sink) { set == null || set.contains(it) }
        }

        /**
         * Commit an `fc` local over each registering function's context, the LSDA slot being
         * [SjljAbi.LSDA_OFFSET] into it, unless one an import or a user made covers it.
         */
        fun typeContexts(
            program: Program,
            regs: List<SjljLsdaAnalyzer.Registration>,
            abi: SjljAbi,
            monitor: TaskMonitor,
            sink: DiagnosticSink,
        ): Int {
            val dt = abi.functionContext ?: run {
                sink.warn("sjlj-context-layout", "${SjljAbi.CONTEXT} is not gcc's, so no context is typed", null)
                return 0
            }
            var typed = 0
            for (reg in regs.distinctBy { it.store }) {
                monitor.checkCancelled()
                val fn = program.functionManager.getFunctionContaining(reg.store) ?: continue
                val displacement = lsdaDisplacement(program, reg) ?: continue
                val offset = displacement.toInt() - SjljAbi.LSDA_OFFSET - fn.frameBias(monitor)
                if (commit(fn, offset, dt, sink)) typed += 1
            }
            return typed
        }

        /** The `%ebp` displacement the LSDA store writes. */
        internal fun lsdaDisplacement(program: Program, reg: SjljLsdaAnalyzer.Registration): Long? {
            val insn = program.listing.getInstructionAt(reg.store) ?: return null
            return insn.getOpObjects(0).filterIsInstance<Scalar>().singleOrNull()?.signedValue
        }

        private fun commit(fn: Function, offset: Int, dt: Structure, sink: DiagnosticSink): Boolean {
            val frame = fn.stackFrame
            val span = offset until offset + dt.length
            val overlapping = frame.stackVariables.filter { v ->
                v.stackOffset < span.last + 1 && v.stackOffset + v.length > span.first
            }
            if (overlapping.any { it.isContext(dt, offset) }) return false
            if (overlapping.any { it.source == SourceType.IMPORTED || it.source == SourceType.USER_DEFINED }) {
                sink.debug("sjlj-context-taken", "a defined local covers ${fn.name}'s context", fn.entryPoint)
                return false
            }
            overlapping.forEach { fn.removeVariable(it) }
            val name = generateSequence(LOCAL) { "${it}_" }.first { n -> fn.allVariables.none { it.name == n } }
            return try {
                frame.createVariable(name, offset, dt, SourceType.ANALYSIS)
                true
            } catch (e: InvalidInputException) {
                sink.warn("sjlj-context-error", "${fn.name}: $e", fn.entryPoint)
                false
            } catch (e: DuplicateNameException) {
                sink.warn("sjlj-context-error", "${fn.name}: $e", fn.entryPoint)
                false
            }
        }

        private fun Variable.isContext(dt: DataType, offset: Int) = stackOffset == offset && dataType.isEquivalent(dt)

        /**
         * Give each gcc EH entry point in [program] its [SjljAbi.signature], by name with or without the
         * PE underscore, where its signature is no more than analysis'. A stripped binary names neither
         * its personality routine nor `_Unwind_SjLj_Register`, but its registrations give both: what they
         * store, and what each calls first after its stores.
         */
        fun typeEntryPoints(
            program: Program,
            regs: List<SjljLsdaAnalyzer.Registration>,
            abi: SjljAbi,
            monitor: TaskMonitor,
            sink: DiagnosticSink,
            covers: (Address) -> Boolean = { true },
        ): Int {
            val fm = program.functionManager
            val byName = mutableMapOf<Function, String>()
            for (fn in fm.getFunctions(true).iterator().asSequence() + fm.externalFunctions.iterator().asSequence()) {
                monitor.checkCancelled()
                val name = fn.name.takeIf { abi.signature(it) != null }
                    ?: fn.name.removePrefix("_").takeIf { abi.signature(it) != null }
                    ?: continue
                byName[fn] = name
            }
            fun unnamed(fn: Function?, name: String) {
                if (fn != null && fn !in byName && fn.symbol.source == SourceType.DEFAULT) byName[fn] = name
            }
            regs.map { it.personality }.distinct().forEach { unnamed(fm.getFunctionAt(it), SjljAbi.PERSONALITY) }
            registerCallee(program, regs)?.let { unnamed(fm.getFunctionAt(it), SjljAbi.REGISTER) }

            var typed = 0
            for ((fn, name) in byName) {
                monitor.checkCancelled()
                if (!covers(fn.entryPoint)) continue
                val sig = abi.signature(name) ?: continue
                if (apply(fn, name, sig, sink)) typed += 1
            }
            return typed
        }

        /** What most registrations call first after their stores: `_Unwind_SjLj_Register(&fc)`. */
        private fun registerCallee(program: Program, regs: List<SjljLsdaAnalyzer.Registration>) = regs
            .mapNotNull { reg ->
                program.listing.getInstructions(reg.store, true).iterator().asSequence()
                    .take(REGISTER_SCAN)
                    .firstOrNull { it.flowType.isCall }
                    ?.flows?.singleOrNull()
            }
            .groupingBy { it }.eachCount()
            .maxByOrNull { it.value }
            ?.takeIf { it.value * 2 > regs.size }
            ?.key

        private fun apply(fn: Function, name: String, sig: SjljAbi.Signature, sink: DiagnosticSink): Boolean {
            // No stab says a function never returns, so that is the ABI's even where they give the rest.
            if (sig.noReturn && !fn.hasNoReturn()) fn.setNoReturn(true)
            if (fn.signatureSource == SourceType.IMPORTED || fn.signatureSource == SourceType.USER_DEFINED) return false
            if (fn.has(sig)) return false
            val program = fn.program
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
                sink.warn("sjlj-signature-error", "$name: $e", fn.entryPoint)
                false
            } catch (e: DuplicateNameException) {
                sink.warn("sjlj-signature-error", "$name: $e", fn.entryPoint)
                false
            }
        }

        /** Whether [fn] is already [sig], as an earlier run left it. */
        private fun Function.has(sig: SjljAbi.Signature) = signatureSource == SourceType.ANALYSIS &&
            callingConventionName == "__cdecl" && returnType.isEquivalent(sig.ret) &&
            parameters.size == sig.params.size &&
            parameters.zip(sig.params).all { (p, s) -> p.name == s.first && p.dataType.isEquivalent(s.second) }

        /** How far past the LSDA store `call _Unwind_SjLj_Register` may be, in instructions. */
        private const val REGISTER_SCAN = 16
    }
}
