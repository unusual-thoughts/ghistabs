package ghistabs.entrypoints

import ghidra.app.cmd.disassemble.DisassembleCommand
import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.DwarfEncodingModeDataType
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAHeader
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.function.OverlappingFunctionException
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.data.AlignmentDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.SignedLeb128DataType
import ghidra.program.model.data.UnsignedLeb128DataType
import ghidra.program.model.lang.OperandType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.util.CodeUnitInsertionException
import ghidra.util.bytesearch.*
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.MessageLogSink
import ghistabs.eh.SjljAbi
import ghistabs.eh.SjljLsda
import ghistabs.entrypoints.SjljLsdaAnalyzer.Companion.layUnreferenced
import ghistabs.entrypoints.SjljLsdaAnalyzer.Companion.traceStore
import ghistabs.forceCreateData
import ghistabs.plus
import java.util.*
import kotlin.math.abs

/**
 * Lays the LSDA of every function MinGW's gcc built with SJLJ exceptions: the header, call-site,
 * action and type tables [SjljLsda] reads, each field typed and commented, labelled `lsda` in the
 * namespace of the function it belongs to. The header and action records are laid by Ghidra's own
 * `LSDAHeader` and `LSDAActionTable`, so they read as the DWARF tables Ghidra lays do.
 *
 * Ghidra's `GCC Exception Handlers` analyzer lays the same tables, but finds them through the
 * `.eh_frame` FDEs of DWARF unwinding, which an SJLJ binary has none of, and reads DWARF call-site
 * records, which SJLJ's are not. The only pointer to an SJLJ LSDA is in its function's prologue,
 * which fills an `_Unwind_SjLj_Function_context` before `_Unwind_SjLj_Register`, the personality
 * routine and then the LSDA, one word above it, usually back to back but sometimes with the
 * scheduler's other prologue stores in between:
 * ```
 * movl $___gxx_personality_sj0, -0x28(%ebp)
 * movl $LLSDA123, -0x24(%ebp)
 * ```
 * so the pair is what this looks for, in the bytes, before or without disassembly. The personality
 * is whatever every such pair stores first: a stripped binary has no `___gxx_personality_sj0` to
 * look up, so a target is taken as one when it is named one, or when at least [MIN_UNNAMED] of
 * the LSDAs stored after it, and nine in ten of them, parse.
 *
 * Runs before the Stabs Importer, whose data-coverage report would otherwise count every table
 * gcc linked into `.text` as undescribed data. The type table's pointers show whatever labels its
 * typeinfo objects get, from the symbol table or the import, so nothing here depends on those.
 */
class SjljLsdaAnalyzer :
    AbstractAnalyzer(
        NAME,
        "Lay the exception tables (LSDA) of gcc SJLJ exception handling, found through the personality " +
            "and LSDA a function stores in its unwind context.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        // Before the Filler Byte Condenser: the padding after a landing pad's `call _Unwind_SjLj_Resume`
        // only leads an undefined run once the receiver and its pads are disassembled.
        priority = AnalysisPriority.LOW_PRIORITY.before().before()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    /** gcc's, as [GnuDemangler.canDemangle] decides it, on 32-bit x86: the only prologue [registrations] reads. */
    override fun canAnalyze(program: Program) = program.language.processor.toString() == "x86" &&
        !program.language.isBigEndian &&
        program.defaultPointerSize == 4 &&
        GnuDemangler().canDemangle(program)

    override fun added(program: Program, set: AddressSetView?, monitor: TaskMonitor, log: MessageLog): Boolean {
        val laid = layAll(program, set ?: program.memory, monitor, MessageLogSink(log, originator = NAME))
        if (laid > 0) log.appendMsg(NAME, "laid $laid LSDA(s)")
        return true
    }

    /**
     * A function's `movl $personality, d(%ebp)` / `movl $lsda, d+4(%ebp)`, [store] being the second, and
     * the receiver its `movl $resume, d+12(%ebp)` stores into `jbuf[1]`, when one is near.
     */
    data class Registration(
        val store: Address,
        val personality: Address,
        val lsda: Address,
        val resume: Address? = null,
    )

    companion object {
        const val NAME = "GCC SJLJ exception tables"
        const val LABEL = "lsda"
        const val RESUME_LABEL = "sjlj_dispatch"

        /** The fewest LSDAs that make an unnamed target the personality routine. */
        const val MIN_UNNAMED = 3

        /** How far past the personality store its LSDA store may be: gcc's furthest is a few instructions. */
        const val WINDOW = 64

        /** How many instructions past the LSDA store [traceStore] follows. */
        private const val TRACE = 16

        /** The alignment gcc gives an LSDA with a type table, padding with zeros. */
        private const val ALIGN = 4

        /** `c7 /0`, `mov r/m32, imm32`, its ModRM `[ebp + disp8]` (mod 01) or `[ebp + disp32]` (mod 10). */
        private const val MOV_IMM32_EBP = "11000111 ..000101"

        /**
         * Lay every LSDA a registration in [set] stores, then the unreferenced ones packed after each
         * ([layUnreferenced]); returns how many in all.
         */
        fun layAll(program: Program, set: AddressSetView, monitor: TaskMonitor, sink: DiagnosticSink): Int {
            val laid = sortedMapOf<Address, Long>()
            for ((lsda, found) in lsdas(program, set, monitor)) {
                monitor.checkCancelled()
                val (parsedLsda, regs) = found
                regs.forEach { layResume(program, it, monitor, sink) }
                parsedLsda ?: run {
                    sink.warn("lsda-unparsed", "no SJLJ LSDA where ${regs.first().store} stores one", lsda)
                    continue
                }
                if (lay(program, lsda, parsedLsda, sink)) {
                    label(program, lsda, regs)
                    laid[lsda] = parsedLsda.size
                }
            }
            return laid.size + layUnreferenced(program, laid, monitor, sink)
        }

        /**
         * The linker keeps the `.gcc_except_table` of every COMDAT copy it discards, so the LSDAs the
         * kept functions store are interleaved with ones nothing stores. From the end of each laid LSDA
         * up to the next, lay each that parses, after the up-to-3 zero bytes that align one with a
         * type table, until a byte that starts none.
         */
        private fun layUnreferenced(
            program: Program,
            laid: SortedMap<Address, Long>,
            monitor: TaskMonitor,
            sink: DiagnosticSink,
        ): Int {
            val memory = program.memory
            fun isZero(at: Address) = runCatching { memory.getByte(at).toInt() == 0 }.getOrDefault(false)
            val starts = laid.keys.toList()
            var count = 0
            for ((i, start) in starts.withIndex()) {
                monitor.checkCancelled()
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
                    if (!lay(program, next, lsda, sink)) break
                    if (pad > 0) program.forceCreateData(at, AlignmentDataType(), pad)
                    count += 1
                    at = next + lsda.size
                }
            }
            return count
        }

        /**
         * Every LSDA a registration in [set] stores after a personality routine, parsed or null if its
         * bytes are not one, with the registrations that store it.
         */
        fun lsdas(
            program: Program,
            set: AddressSetView,
            monitor: TaskMonitor,
        ): Map<Address, Pair<SjljLsda?, List<Registration>>> {
            val parsed = mutableMapOf<Address, SjljLsda?>()
            fun lsdaAt(at: Address) = parsed.getOrPut(at) { SjljLsda.parse(program, at) }

            return registrations(program, set, monitor).groupBy { it.personality }.filter { (personality, regs) ->
                isPersonality(program, personality) || regs.map { it.lsda }.distinct().let { all ->
                    val parsing = all.count { lsdaAt(it) != null }
                    parsing >= MIN_UNNAMED && parsing * 10 >= all.size * 9
                }
            }.values.flatten().groupBy { it.lsda }.mapValues { (at, regs) -> lsdaAt(at) to regs }
        }

        private fun isPersonality(program: Program, at: Address) =
            program.symbolTable.getSymbols(at).any { it.name.endsWith("personality_sj0") }

        /**
         * Every personality/LSDA store pair in the executable bytes of [set], whose two immediates both
         * land in memory: a `movl $imm32, d(%ebp)` and, within [WINDOW] bytes after it, one to `d+4`.
         * gcc schedules the prologue, so the two need not be adjacent, and either may take a disp8 or
         * a disp32 whichever side of -128 its slot falls.
         */
        fun registrations(program: Program, set: AddressSetView, monitor: TaskMonitor): List<Registration> {
            val memory = program.memory
            val space = program.addressFactory.defaultAddressSpace
            fun target(store: Store) =
                runCatching { space.getAddress(store.immediate) }.getOrNull()?.takeIf { memory.contains(it) }

            val stores = StoreSearch(program).apply { search(program, set, monitor) }.stores.sortedBy { it.at }
            val disassembler = PseudoDisassembler(program)
            return stores.withIndex().mapNotNull { (k, first) ->
                val personality = target(first) ?: return@mapNotNull null
                val after = first.at + first.length.toLong()
                val second = stores.drop(k + 1).asSequence()
                    .takeWhile { it.at.subtract(after) < WINDOW }
                    .firstOrNull { it.at >= after && it.displacement == first.displacement + 4 }
                    ?: return@mapNotNull null
                val lsda = target(second) ?: return@mapNotNull null
                val jbuf1 = second.displacement + SjljAbi.RESUME_FROM_LSDA
                val resume = (
                    near(stores, first.at, second.at)
                        .filter { it.displacement == jbuf1 }
                        .minByOrNull { abs(it.at.subtract(second.at)) }
                        ?.immediate
                        ?: traceStore(disassembler, second.at, jbuf1)
                    )?.let { runCatching { space.getAddress(it) }.getOrNull() }?.takeIf { memory.contains(it) }
                Registration(second.at, personality, lsda, resume)
            }
        }

        /**
         * The [stores] within [WINDOW] of [from] to [to], either side: gcc schedules the `__builtin_setjmp`
         * stores among the prologue's, before the personality's as well as after the LSDA's.
         */
        private fun near(stores: List<Store>, from: Address, to: Address): Sequence<Store> {
            val start = stores.binarySearchBy(from.subtract(WINDOW.toLong()).offset) { it.at.offset }
                .let { if (it < 0) -it - 1 else it }
            return stores.asSequence().drop(start).takeWhile { it.at.offset <= to.offset + WINDOW }
        }

        /**
         * The immediate the straight-line code after [from] stores to `[displacement](%ebp)` through a
         * register, as gcc 3.x's `__builtin_setjmp` setup does:
         * ```
         * lea -0xdc(%ebp),%eax   ; &jbuf
         * mov $L, %edx
         * mov %edx, 0x4(%eax)    ; jbuf[1] = L
         * ```
         * Registers are followed through `lea d(%ebp)` and `mov $imm`; anything else that writes one
         * forgets it. Stops at the first instruction that does not fall through.
         */
        private fun traceStore(disassembler: PseudoDisassembler, from: Address, displacement: Long): Long? {
            val regs = StoreTrace()
            var at = from
            repeat(TRACE) {
                val insn = runCatching { disassembler.disassemble(at) }.getOrNull() ?: return null
                if (!insn.flowType.isFallthrough) return null
                regs.step(insn, displacement)?.let { return it }
                at += insn.length.toLong()
            }
            return null
        }

        /** The registers [traceStore] follows: an `%ebp` displacement each holds, or an immediate. */
        private class StoreTrace {
            private val frame = mutableMapOf<String, Long>()
            private val imm = mutableMapOf<String, Long>()

            /** Follow [insn]; the immediate it stores to `[displacement](%ebp)`, if it does. */
            fun step(insn: Instruction, displacement: Long): Long? {
                val dest = reg(insn, 0)
                var tracked: String? = null
                when (insn.mnemonicString) {
                    "LEA" if dest != null -> base(insn, 1)?.let {
                        set(dest.name, it, frame, imm)
                        tracked = dest.name
                    }

                    "MOV" if dest == null && OperandType.isDynamic(insn.getOperandType(0)) ->
                        (insn.getScalar(1)?.unsignedValue ?: reg(insn, 1)?.let { imm[it.name] })
                            ?.takeIf { base(insn, 0) == displacement }?.let { return it }

                    "MOV" if dest != null && OperandType.isScalar(insn.getOperandType(1)) ->
                        insn.getScalar(1)?.unsignedValue?.let {
                            set(dest.name, it, imm, frame)
                            tracked = dest.name
                        }
                }
                insn.resultObjects.filterIsInstance<Register>().filter { it.name != tracked }.forEach {
                    frame.remove(it.name)
                    imm.remove(it.name)
                }
                return null
            }

            private fun set(name: String, value: Long, into: MutableMap<String, Long>, from: MutableMap<String, Long>) {
                into[name] = value
                from.remove(name)
            }

            private fun reg(insn: Instruction, i: Int) = insn.getOpObjects(i).singleOrNull() as? Register

            /** The `%ebp` displacement operand [i] addresses, directly or through a followed register. */
            private fun base(insn: Instruction, i: Int): Long? {
                val objs = insn.getOpObjects(i)
                val r = objs.filterIsInstance<Register>().singleOrNull()?.takeIf { objs.size <= 2 } ?: return null
                val k = objs.filterIsInstance<Scalar>().singleOrNull()?.signedValue ?: 0
                return if (r.name == "EBP") k else frame[r.name]?.plus(k)
            }
        }

        /**
         * Label [reg]'s receiver `sjlj_dispatch_<address>` and
         * disassemble it, with the code it flows to, into the function's body: the unwinder `longjmp`s to
         * it, so no flow from the entry reaches it, nor the landing pads it dispatches to.
         */
        fun layResume(program: Program, reg: Registration, monitor: TaskMonitor, sink: DiagnosticSink) {
            val at = reg.resume ?: return
            val fm = program.functionManager
            val fn = fm.getFunctionContaining(reg.store) ?: return
            val listing = program.listing
            if (fm.getFunctionAt(at) != null || !program.memory.executeSet.contains(at)) return
            if (listing.getInstructionAt(at) == null) {
                if (listing.getDefinedDataContaining(at) != null || listing.getInstructionContaining(at) != null) {
                    sink.warn("sjlj-resume-occupied", "receiver of ${fn.name} is inside other code or data", at)
                    return
                }
                DisassembleCommand(at, null, true).applyTo(program, monitor)
                listing.getInstructionAt(at) ?: return sink.warn("sjlj-resume-undecoded", "receiver of ${fn.name}", at)
            }
            // Within the function's extent: gcc puts the receiver and its landing pads there, and a flow
            // past it may be a function nothing has defined yet, which the stabs import would then find taken.
            val flow = CreateFunctionCmd.getFunctionBody(program, at, monitor)
                .intersect(AddressSet(fn.entryPoint, fn.body.maxAddress))
            if (!fn.body.contains(flow)) {
                try {
                    fn.body = fn.body.union(flow)
                } catch (e: OverlappingFunctionException) {
                    sink.warn("sjlj-resume-overlap", "receiver of ${fn.name} runs into another function: $e", at)
                }
            }
            // Global, as the LSDA header's is: the decompiler names no label in a function's namespace,
            // and with this one `fc.jbuf.resume = &sjlj_dispatch_<address>`.
            val symtab = program.symbolTable
            val name = "${RESUME_LABEL}_$at"
            if (symtab.getSymbols(at).none { it.name == name }) {
                symtab.createLabel(at, name, SourceType.ANALYSIS).setPrimary()
            }
            listing.setComment(
                at,
                CommentType.PRE,
                "SJLJ receiver (jbuf[1]): the unwinder longjmps here to dispatch on call_site to a landing pad",
            )
        }

        /** A `movl $immediate, displacement(%ebp)` of [length] bytes at [at]. */
        private class Store(val at: Address, val length: Int, val displacement: Long, val immediate: Long)

        /**
         * Ghidra's byte pattern search for `c7 /0` with an `[ebp + disp]` ModRM, either displacement
         * width, each match then decoded by Ghidra's disassembler: a `MOV` of an immediate to a
         * dword at `EBP` plus a displacement is a store.
         */
        private class StoreSearch(val program: Program) : MemoryBytePatternSearcher(NAME) {
            val stores = mutableListOf<Store>()
            private val disassembler = PseudoDisassembler(program)

            init {
                setSearchExecutableOnly(true)
                addPattern(Pattern(DittedBitSequence(MOV_IMM32_EBP), 0, arrayOf(), arrayOf(DummyMatchAction())))
            }

            override fun preMatchApply(actions: Array<MatchAction>, address: Address) {
                val insn = runCatching { disassembler.disassemble(address) }.getOrNull() ?: return
                if (insn.mnemonicString != "MOV" || insn.numOperands != 2) return
                val dest = insn.getOpObjects(0)
                if (dest.none { it is Register && it.name == "EBP" }) return
                val displacement = dest.filterIsInstance<Scalar>().singleOrNull()?.signedValue ?: return
                val immediate = insn.getScalar(1)?.unsignedValue ?: return
                stores += Store(address, insn.length, displacement, immediate)
            }
        }

        /**
         * Lay [lsda]'s fields at [at], unless a function's body covers them: then the pair was not a
         * registration. Ghidra's [LSDAHeader] lays the header, labelled `lsda_exception_table_<address>`,
         * and its [LSDAActionTable] the action records; the call sites, which are not the DWARF records
         * its `LSDACallSiteTable` reads, and the type table and exception specs, which its
         * `LSDATypeTable` can only reach through that call-site parse, are laid from [lsda]. Ghidra's
         * classes skip a field whose bytes already hold data, so the extent is cleared first.
         */
        private fun lay(program: Program, at: Address, lsda: SjljLsda, sink: DiagnosticSink): Boolean {
            val end = at + (lsda.size - 1)
            if (program.functionManager.getFunctionsOverlapping(AddressSet(at, end)).hasNext()) {
                sink.warn("lsda-in-function", "LSDA would cover ${lsda.size} bytes of a function", at)
                return false
            }
            program.listing.clearCodeUnits(at, end, false)
            val headerEnd = try {
                layWithGhidra(program, at, lsda)
            } catch (e: MemoryAccessException) {
                sink.warn("lsda-lay-error", "Ghidra's LSDA classes: $e", at)
                null
            }
            val ours = lsda.items.filter {
                headerEnd == null || (it.at >= headerEnd && it.kind != SjljLsda.Kind.SLEB128)
            }
            val dtm = program.dataTypeManager
            for ((addr, length, kind, comment) in ours) {
                val dt = when (kind) {
                    SjljLsda.Kind.ENCODING -> DwarfEncodingModeDataType.dataType
                    SjljLsda.Kind.ULEB128 -> UnsignedLeb128DataType.dataType
                    SjljLsda.Kind.SLEB128 -> SignedLeb128DataType.dataType
                    SjljLsda.Kind.POINTER -> PointerDataType(dtm)
                    SjljLsda.Kind.ALIGNMENT -> AlignmentDataType()
                }
                try {
                    program.forceCreateData(addr, dt, length)
                } catch (e: CodeUnitInsertionException) {
                    sink.warn("lsda-lay-error", "${dt.name}: $e", addr)
                    continue
                }
                program.listing.setComment(addr, CommentType.EOL, comment)
            }
            return true
        }

        /** Lay [lsda]'s header and action records with Ghidra's classes; returns the address past the header. */
        private fun layWithGhidra(program: Program, at: Address, lsda: SjljLsda): Address {
            val region = RegionDescriptor(program.memory.getBlock(at))
            val header = LSDAHeader(TaskMonitor.DUMMY, program, region)
            header.create(at)
            if (lsda.actions.isNotEmpty()) {
                LSDAActionTable(TaskMonitor.DUMMY, program, region)
                    .create(lsda.actions.first().at, lsda.actions.last().at)
            }
            return header.nextAddress
        }

        /** `lsda` in each storing function's namespace, beside the header's global label. */
        private fun label(program: Program, at: Address, regs: List<Registration>) {
            regs.mapNotNull { program.functionManager.getFunctionContaining(it.store) }.distinct()
                .forEach { program.symbolTable.createLabel(at, LABEL, it, SourceType.ANALYSIS) }
        }
    }
}
