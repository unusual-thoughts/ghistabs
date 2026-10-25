package ghistabs.cpp.eh

import ghidra.app.util.PseudoDisassembler
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.lang.OperandType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.util.bytesearch.*
import ghidra.util.task.TaskMonitor
import ghistabs.minus
import ghistabs.plus
import kotlin.math.abs

/**
 * One function's SJLJ registration, as its prologue fills its `SjLj_Function_Context`: the
 * `movl $personality, d(%ebp)` / `movl $lsda, d+4(%ebp)` pair, [store] being the second and
 * [lsdaDisplacement] its `d+4`, and the receiver its `movl $resume, d+12(%ebp)` stores into
 * `jbuf[1]`, when one is near.
 */
data class Registration(
    val store: Address,
    val lsdaDisplacement: Long,
    val personality: Address,
    val lsda: Address,
    val resume: Address? = null,
)

/** An LSDA the registrations in [registrations] store: [lsda] parsed, or null if its bytes are not one. */
data class StoredLsda(val lsda: SjljLsda?, val registrations: List<Registration>)

/** The fewest LSDAs that make an unnamed target the personality routine. */
const val MIN_UNNAMED_PERSONALITY = 3

/** How far past the personality store its LSDA store may be: gcc's furthest is a few instructions. */
private const val WINDOW = 64

/** How many instructions past the LSDA store [traceStore] follows. */
private const val TRACE = 16

/** `c7 /0`, `mov r/m32, imm32`, its ModRM `[ebp + disp8]` (mod 01) or `[ebp + disp32]` (mod 10). */
private const val MOV_IMM32_EBP = "11000111 ..000101"

/**
 * Every LSDA a registration in [set] stores after a personality routine, by its address. The
 * personality is whatever every such pair stores first: a stripped binary has no
 * `___gxx_personality_sj0` to look up, so a target is taken as one when it is named one, or when at
 * least [MIN_UNNAMED_PERSONALITY] of the LSDAs stored after it, and nine in ten of them, parse.
 */
fun Program.sjljLsdas(set: AddressSetView, monitor: TaskMonitor): Map<Address, StoredLsda> {
    val parsed = mutableMapOf<Address, SjljLsda?>()
    fun lsdaAt(at: Address) = parsed.getOrPut(at) { SjljLsda.parse(this, at) }

    return sjljRegistrations(set, monitor).groupBy { it.personality }.filter { (personality, regs) ->
        isPersonality(personality) || regs.map { it.lsda }.distinct().let { all ->
            val parsing = all.count { lsdaAt(it) != null }
            parsing >= MIN_UNNAMED_PERSONALITY && parsing * 10 >= all.size * 9
        }
    }.values.flatten().groupBy { it.lsda }.mapValues { (at, regs) -> StoredLsda(lsdaAt(at), regs) }
}

private fun Program.isPersonality(at: Address) = symbolTable.getSymbols(at).any { it.name.endsWith("personality_sj0") }

/**
 * Every personality/LSDA store pair in the executable bytes of [set], whose two immediates both land
 * in memory: a `movl $imm32, d(%ebp)` and, within [WINDOW] bytes after it, one to `d+4`. gcc
 * schedules the prologue, so the two need not be adjacent, and either may take a disp8 or a disp32
 * whichever side of -128 its slot falls. Read from the bytes, so before or without disassembly.
 */
fun Program.sjljRegistrations(set: AddressSetView, monitor: TaskMonitor): List<Registration> {
    val space = addressFactory.defaultAddressSpace
    fun address(offset: Long) = runCatching { space.getAddress(offset) }.getOrNull()?.takeIf { memory.contains(it) }

    val stores = StoreSearch(this).apply { search(this@sjljRegistrations, set, monitor) }.stores.sortedBy { it.at }
    val disassembler = PseudoDisassembler(this)
    return stores.withIndex().mapNotNull { (k, first) ->
        val personality = address(first.immediate) ?: return@mapNotNull null
        val after = first.at + first.length.toLong()
        val second = stores.drop(k + 1).asSequence()
            .takeWhile { it.at - after < WINDOW }
            .firstOrNull { it.at >= after && it.displacement == first.displacement + 4 }
            ?: return@mapNotNull null
        val lsda = address(second.immediate) ?: return@mapNotNull null
        val jbuf1 = second.displacement + SjljAbi.RESUME_FROM_LSDA
        val resume = near(stores, first.at, second.at)
            .filter { it.displacement == jbuf1 }
            .minByOrNull { abs(it.at - second.at) }
            ?.immediate
            ?: disassembler.traceStore(second.at, jbuf1)
        Registration(second.at, second.displacement, personality, lsda, resume?.let(::address))
    }
}

/**
 * The [stores] within [WINDOW] of [from] to [to], either side: gcc schedules the `__builtin_setjmp`
 * stores among the prologue's, before the personality's as well as after the LSDA's.
 */
private fun near(stores: List<Store>, from: Address, to: Address): Sequence<Store> {
    val start = stores.binarySearchBy((from - WINDOW.toLong()).offset) { it.at.offset }
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
private fun PseudoDisassembler.traceStore(from: Address, displacement: Long): Long? {
    val regs = StoreTrace()
    var at = from
    repeat(TRACE) {
        val insn = runCatching { disassemble(at) }.getOrNull() ?: return null
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

/** A `movl $immediate, displacement(%ebp)` of [length] bytes at [at]. */
private class Store(val at: Address, val length: Int, val displacement: Long, val immediate: Long)

/**
 * Ghidra's byte pattern search for `c7 /0` with an `[ebp + disp]` ModRM, either displacement width,
 * each match then decoded by Ghidra's disassembler: a `MOV` of an immediate to a dword at `EBP` plus
 * a displacement is a store.
 */
private class StoreSearch(program: Program) : MemoryBytePatternSearcher("SJLJ context stores") {
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
