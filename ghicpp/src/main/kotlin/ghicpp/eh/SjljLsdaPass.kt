package ghicpp.eh

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.DwarfEncodingModeDataType
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAHeader
import ghidra.program.database.function.OverlappingFunctionException
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.AlignmentDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.SignedLeb128DataType
import ghidra.program.model.data.UnsignedLeb128DataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.util.CodeUnitInsertionException
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink
import java.util.*
import kotlin.math.abs

/**
 * Lays gcc SJLJ LSDAs as typed, commented data, labelled [LABEL] in each storing function's namespace,
 * and each registering function's receiver ([layReceiver]). The header and action table use Ghidra's
 * [LSDAHeader] and [LSDAActionTable] so they match its DWARF tables; the rest comes from [SjljLsda].
 */
class SjljLsdaPass(val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val listing = program.listing
    private val fm = program.functionManager

    /** Finds the registrations in [set], lays their receivers, then their LSDAs; returns how many LSDAs. */
    fun run(set: AddressSetView, monitor: TaskMonitor): Int {
        val stored = SjljRegistrationFinder(program).lsdas(set, monitor)
        val regs = stored.values.flatMap { it.registrations }
        monitor.initialize(regs.size.toLong(), "Laying SJLJ receivers")
        for (reg in regs) {
            monitor.increment()
            layReceiver(reg, monitor.cancelOnly)
        }
        return layAll(stored, monitor)
    }

    /**
     * Disassembles [reg]'s receiver and the landing pads it reaches into its function, labelled
     * [RESUME_LABEL]`_<address>`. Only the unwinder's `longjmp` reaches them, so no flow does.
     */
    fun layReceiver(reg: SjljRegistration, monitor: TaskMonitor) {
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
    private fun SjljRegistration.referenceReceiver(fn: Function, at: Address) {
        val (insn, op) = listing.getInstructions(fn.body, true).iterator().asSequence()
            .flatMap { insn -> (0..<insn.numOperands).map { insn to it } }
            .filter { (insn, op) -> insn.getScalar(op)?.unsignedValue == at.offset }
            .minByOrNull { (insn, _) -> abs(insn.address - store) }
            ?: return
        val refs = program.referenceManager
        if (refs.getReferencesFrom(insn.address, op).none { it.toAddress == at && it.referenceType.isFlow }) {
            refs.addMemoryReference(insn.address, at, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, op)
        }
    }

    /** Lays every parsed LSDA in [stored], then the unreferenced ones between them; returns how many. */
    private fun layAll(stored: Map<Address, StoredLsda>, monitor: TaskMonitor): Int {
        val laid = sortedMapOf<Address, Long>()
        monitor.initialize(stored.size.toLong(), "Laying SJLJ LSDAs")
        for ((at, found) in stored) {
            monitor.increment()
            val lsda = found.lsda ?: run {
                warn("lsda-unparsed", "no SJLJ LSDA where ${found.registrations.first().store} stores one", at)
                continue
            }
            if (lsda.lay(at)) {
                label(at, found.registrations)
                laid[at] = lsda.size
            }
        }
        return laid.size + layUnreferenced(laid, monitor)
    }

    /**
     * Lays the LSDAs nothing stores, left by COMDAT copies the linker discarded: after each [laid] one,
     * skipping up to 3 bytes of alignment, until the bytes stop parsing.
     */
    private fun layUnreferenced(laid: SortedMap<Address, Long>, monitor: TaskMonitor): Int {
        fun isZero(at: Address) = runCatching { program.memory.getByte(at).toInt() == 0 }.getOrDefault(false)
        val starts = laid.keys.toList()
        var count = 0
        monitor.initialize(starts.size.toLong(), "Laying unreferenced SJLJ LSDAs")
        for ((i, start) in starts.withIndex()) {
            monitor.increment()
            val limit = starts.getOrNull(i + 1)
            var at = start + laid.getValue(start)
            while (limit == null || at < limit) {
                val pad = (0 until ALIGN).takeWhile { isZero(at + it) }.size
                if (pad == ALIGN) break
                val next = at + pad
                if (next == limit) {
                    program.forceCreateData(at, AlignmentDataType(), pad)
                    break
                }
                val lsda = SjljLsda.parse(program, next) ?: break
                if (limit != null && next + lsda.size > limit) break
                if (!lsda.lay(next)) break
                if (pad > 0) program.forceCreateData(at, AlignmentDataType(), pad)
                count += 1
                at = next + lsda.size
            }
        }
        return count
    }

    /**
     * Lays this LSDA at [at]; false if a function body covers it, so it was no registration. Clears the
     * extent first, since Ghidra's classes skip bytes that already hold data.
     */
    private fun SjljLsda.lay(at: Address): Boolean {
        val end = at + (size - 1)
        if (fm.getFunctionsOverlapping(AddressSet(at, end)).hasNext()) {
            warn("lsda-in-function", "LSDA would cover $size bytes of a function", at)
            return false
        }
        listing.clearCodeUnits(at, end, false)
        val headerEnd = try {
            layWithGhidra(at)
        } catch (e: MemoryAccessException) {
            warn("lsda-lay-error", "Ghidra's LSDA classes: $e", at)
            null
        }
        val ours = items.filter {
            headerEnd == null || (it.at >= headerEnd && it.kind != SjljLsda.Kind.SLEB128)
        }
        for ((addr, length, kind, comment) in ours) {
            val dt = when (kind) {
                SjljLsda.Kind.ENCODING -> DwarfEncodingModeDataType.dataType
                SjljLsda.Kind.ULEB128 -> UnsignedLeb128DataType.dataType
                SjljLsda.Kind.SLEB128 -> SignedLeb128DataType.dataType
                SjljLsda.Kind.POINTER -> PointerDataType(program.dataTypeManager)
                SjljLsda.Kind.ALIGNMENT -> AlignmentDataType()
            }
            try {
                program.forceCreateData(addr, dt, length)
            } catch (e: CodeUnitInsertionException) {
                warn("lsda-lay-error", "${dt.name}: $e", addr)
                continue
            }
            listing.setComment(addr, CommentType.EOL, comment)
        }
        return true
    }

    /** Lay [lsda]'s header and action records with Ghidra's classes; returns the address past the header. */
    private fun SjljLsda.layWithGhidra(at: Address): Address {
        val region = RegionDescriptor(program.memory.getBlock(at))
        val header = LSDAHeader(TaskMonitor.DUMMY, program, region)
        header.create(at)
        if (actions.isNotEmpty()) {
            LSDAActionTable(TaskMonitor.DUMMY, program, region)
                .create(actions.first().at, actions.last().at)
        }
        return header.nextAddress
    }

    /** [LABEL] in each storing function's namespace, beside the header's global label. */
    private fun label(at: Address, regs: List<SjljRegistration>) {
        regs.mapNotNull { fm.getFunctionContaining(it.store) }.distinct()
            .forEach { program.symbolTable.createLabel(at, LABEL, it, SourceType.ANALYSIS) }
    }

    companion object {
        const val LABEL = "lsda"

        /** The receiver's label, `sjlj_dispatch_<address>`. */
        const val RESUME_LABEL = "sjlj_dispatch"

        private const val RECEIVER_COMMENT =
            "SJLJ receiver (jbuf[1]): the unwinder longjmps here to dispatch on call_site to a landing pad"

        /** The alignment gcc gives an LSDA with a type table, padding with zeros. */
        private const val ALIGN = 4
    }
}
