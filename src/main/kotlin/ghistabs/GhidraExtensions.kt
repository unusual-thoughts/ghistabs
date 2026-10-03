@file:Suppress("TooManyFunctions")

package ghistabs

import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.app.util.NamespaceUtils
import ghidra.app.util.PseudoDisassembler
import ghidra.app.util.bin.FileByteProvider
import ghidra.app.util.bin.InputStreamByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.LoaderTier
import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.address.*
import ghidra.program.model.data.*
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.parse.dbxArch
import ghistabs.parse.frameRegister
import java.io.File
import java.nio.file.AccessMode

operator fun Address.plus(rhs: Long): Address = addNoWrap(rhs)
operator fun Address.plus(rhs: Int): Address = addNoWrap(rhs.toLong())

operator fun Address.minus(rhs: Long): Address = subtractNoWrap(rhs)
operator fun Address.minus(rhs: Int): Address = subtractNoWrap(rhs.toLong())
operator fun Address.minus(rhs: Address): Long = subtract(rhs)

/** The empty range at this address. Ghidra spells emptiness `max == min - 1`, which the first address
 *  of a space cannot express — there it is spelled `min == max + 1`, one above. Both are zero-length
 *  and contain nothing. */
private fun Address.emptyRange(): AddressRange = AddressRangeImpl(if (previous() == null) next() else this, 0)

/** `a..b`. Built by length for the same reason as [rangeUntil]: bounds that arrive out of order would
 *  otherwise be swapped into a range that looks valid, so `b..a` would come back as `[a, b]`. */
operator fun Address.rangeTo(rhs: Address): AddressRange = if (rhs < this) emptyRange() else AddressRangeImpl(this, rhs)

/** `a..<b`. Built by length rather than by bounds: the two-address constructor swaps what arrives out
 *  of order, so `a..<a` would come back as `[a-1, a]`, while an empty range contains nothing — the
 *  honest answer for an exclusive end at or below the start. */
operator fun Address.rangeUntil(rhs: Address): AddressRange =
    if (rhs <= this) emptyRange() else AddressRangeImpl(this, rhs - 1)

operator fun AddressSetView.minus(addrs: AddressSetView): AddressSet = subtract(addrs)
operator fun AddressSetView.minus(range: AddressRange): AddressSet = subtract(AddressSet(range))
operator fun AddressSetView.minus(addr: Address): AddressSet = subtract(AddressSet(addr))
operator fun AddressSetView.plus(addrs: AddressSetView): AddressSet = union(addrs)
operator fun AddressSetView.plus(range: AddressRange): AddressSet = union(AddressSet(range))
operator fun AddressSetView.plus(addr: Address): AddressSet = union(AddressSet(addr))

operator fun Data.get(i: Int): Data? = this.getComponent(i)
operator fun Data.get(name: String): Data? =
    (dataType as? Composite)?.components?.firstOrNull { it.fieldName == name }?.ordinal?.let(this::get)
inline fun <reified T> Data.valueOf(name: String): T? = get(name)?.value as? T
fun Data.getScalar(name: String): Scalar? = valueOf(name)

/** Whether the one-bit field [name] is set. */
fun Data.flag(name: String) = getScalar(name)?.unsignedValue == 1L

fun Iterable<AddressRange>.gapsIn(range: AddressRange, action: (AddressRange) -> Unit = { }) = sequence {
    var start = range.minAddress
    for (r in this@gapsIn) {
        action(r)
        (start..<r.minAddress).takeIf { it.length > 0 }?.let { yield((it)) }
        if (r.maxAddress >= range.maxAddress) return@sequence
        start = r.maxAddress.next()
    }
    (start..range.maxAddress).takeIf { it.length > 0 }?.let { yield((it)) }
}

fun Iterable<AddressRange>.monitoredGapsIn(range: AddressRange, monitor: TaskMonitor? = null) = gapsIn(range) {
    monitor?.progress = it.minAddress - range.minAddress
}

/** Undefined runs in [range] — the gaps between instructions and defined data, as `getUndefinedRanges` walks them. */
fun Listing.undefinedRangesIn(range: AddressRange, monitor: TaskMonitor? = null) = getCodeUnits(AddressSet(range), true)
    .filter { (it as? Data)?.isDefined != false } // instructions + defined data
    .map { it.range }
    .monitoredGapsIn(range, monitor)

/** The two [ghidra.program.model.listing.AutoParameterType] display names. */
private val INJECTED_PARAM_NAMES = setOf(Function.THIS_PARAM_NAME, Function.RETURN_PTR_PARAM_NAME)

/** The convention's parameter, not the source's: an auto-param, or the stored copy of one left by an
 *  analyzer that committed in custom storage. */
val Parameter.isInjected get() = isAutoParameter || name in INJECTED_PARAM_NAMES

/** A local wearing an injected parameter's name — it blocks the auto-param a convention change reinstates. */
val Variable.collidesWithInjectedParameter get() = name in INJECTED_PARAM_NAMES

inline val FunctionManager.functionsIterable get() = this.getFunctions(true) as Iterable<Function>
inline val FunctionManager.functions get() = functionsIterable.asSequence()
inline val Program.functions get() = functionManager.functions

/** find a function, if any, such that [addr] falls within its convex hull [entry, body.maxAddress]  */
fun FunctionManager.getFunctionWrapping(addr: Address) = getFunctionContaining(addr)
    ?: getFunctions(addr, false).asIterable().firstOrNull()?.takeIf { addr <= it.body.maxAddress }

/** [addr] falls within the convex hull [entry, body.maxAddress] of a function. */
fun FunctionManager.inHull(addr: Address) = getFunctionWrapping(addr) != null

val Function.isMethod get() = parentNamespace is GhidraClass

/** Creates a hierarchy of namespaces, named [parts], in [parent] or Global namespace, with [sourceType],
 *  the final of which will be a [GhidraClass]
 */
fun SymbolTable.buildClassNamespaces(
    parts: List<String>,
    sourceType: SourceType = SourceType.IMPORTED,
    parent: Namespace? = null,
): GhidraClass {
    var ns = parent
    for ((i, part) in parts.withIndex()) {
        val isLast = i == parts.lastIndex
        val existing = getNamespace(part, ns)
        ns = when (existing) {
            null if isLast -> createClass(ns, part, sourceType)
            null -> createNameSpace(ns, part, sourceType)
            else if (isLast && existing !is GhidraClass) -> NamespaceUtils.convertNamespaceToClass(existing)
            else -> existing
        }
    }
    return ns as GhidraClass
}

/**
 * [Program] rather than `DomainObject`: 11.1 folded `UndoableDomainObject`'s transaction API into
 * `DomainObject`, but a Program reaches it either way — so this needs no version-variant source.
 */
fun <T> Program.runTransaction(description: String = "Kotlin Lambda Transaction", transaction: () -> T): T =
    startTransaction(description).let { txID ->
        return try {
            transaction().also { endTransaction(txID, true) }
        } catch (e: Throwable) {
            endTransaction(txID, false)
            throw e
        }
    }

fun <T> DataTypeManager.runTransaction(description: String = "Kotlin Lambda Transaction", transaction: () -> T): T =
    startTransaction(description).let { txID ->
        return try {
            transaction().also { endTransaction(txID, true) }
        } catch (e: Throwable) {
            endTransaction(txID, false)
            throw e
        }
    }

val DataType.nameWithoutConflict: String get() = DataTypeUtilities.getNameWithoutConflict(this, false)
fun DataType.isConflict() = nameWithoutConflict != name
fun DataTypeManager.conflictBase(dt: DataType): DataType? = getDataType(dt.categoryPath, dt.nameWithoutConflict)
fun CategoryPath.at(name: String) = DataTypePath(this, name)

val CodeUnit.range get() = minAddress..maxAddress

/**
 * Clear any instructions covering [range]; true if there were any. An empty [range]
 * (a `Dynamic` type that would not resolve) clears nothing rather than guess a span.
 *
 * *Anywhere* in the range, not just at its first byte: `createData` refuses the whole span if one
 * instruction sits in it, wherever that is, so testing only the start left the caller's create to
 * throw — which is how a single stray NOP at the end of an alignment run cost the run its Alignment.
 */
fun Listing.clearAnyDisassembly(range: AddressRange): Boolean {
    val covered = range.length != 0L && (
        getInstructionContaining(range.minAddress) != null ||
            getInstructions(AddressSet(range.minAddress, range.maxAddress), true).hasNext()
        )
    if (!covered) return false
    clearCodeUnits(range.minAddress, range.maxAddress, false)
    return true
}

/**
 * Lay [dt] at [addr] over whatever is there — conflicting data *and* disassembly. Every
 * [DataUtilities.ClearDataMode] clears data only, and createData refuses an instruction address
 * outright, so a caller that knows the address holds data has to clear the code itself.
 *
 * [length] is both what gets cleared and what createData is given; a `Dynamic` type passing -1 sizes
 * itself and so clears nothing. [onClearedCode] fires only when there was disassembly to remove, for
 * a caller that wants to count or report it. Throws like the API it wraps.
 */
fun Program.forceCreateData(
    addr: Address,
    dt: DataType,
    length: Int = dt.length,
    onClearedCode: () -> Unit = {},
): Data {
    if (listing.clearAnyDisassembly(addr..<addr + length)) onClearedCode()
    return DataUtilities.createData(this, addr, dt, length, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
}

/**
 * [dt] read over the bytes at [addr] without laying anything in the listing, or null if they are not
 * all readable. The data type does the decoding — width, endianness, sign, which address space a
 * pointer lands in — so a caller never reassembles bytes by hand.
 */
fun Program.readAt(addr: Address, dt: DataType): Data? = PseudoDisassembler(this).applyDataType(addr, dt)

/** [readAt]'s value as a [T]: a [Scalar] for an integer type, an [Address] for a pointer. */
inline fun <reified T> Program.readAs(addr: Address, dt: DataType): T? = readAt(addr, dt)?.value as? T

/**
 * The pointer stored at [addr], taken as it stands. The loader has already relocated what memory
 * holds, so this is the address it points at in the program as loaded.
 */
fun Program.readPointer(addr: Address): Address? = readAs(addr, PointerDataType(dataTypeManager))

val MemoryBlock.byteProvider get() = InputStreamByteProvider(data, size)

/**
 * Where the program's default calling convention starts its stack parameters — the bias between a
 * gcc frame offset and a Ghidra one.
 *
 * The *default* convention, not [ghidra.program.model.listing.VariableUtilities.getBaseStackParamOffset]'s
 * per-function answer: x86gcc gives `processEntry` `stackshift="0"` against `__cdecl`'s 4,
 * so asking whichever function a caller had first could shift every stack slot in the program by a pointer.
 * Fallback as Ghidra's, for a convention with no stack ParamEntry to derive an offset from.
 */
val Program.baseStackParamOffset get() = compilerSpec.defaultCallingConvention.run {
    stackParameterOffset?.toInt() ?: stackshift
}

/**
 * How many instructions from the entry a prologue may take to set up its frame pointer. The scan also
 * stops at the first instruction that does not simply fall through, so this only bounds a straight run.
 */
private const val PROLOGUE_SCAN = 32

private val Program.stackPointer get() = compilerSpec.stackPointer

/** The register gcc's stab frame offsets count from, or null when [dbxArch] doesn't know this processor. */
private val Program.framePointer get() = dbxArch?.frameRegister?.let(::getRegister)

/**
 * How far below the entry SP this function's prologue set the frame pointer that gcc's stab offsets
 * count from. On x86 that is usually the one saved-FP push [Program.baseStackParamOffset] implies, but a
 * realigning `main` (gcc >= 4.1: `lea 4(%esp),%ecx; and $-16,%esp; push -4(%ecx); push %ebp`) sits a copied
 * return address deeper (Ghidra tracks the `and` at depth 0 as no change). On SPARC, `save`'s p-code copies
 * `fp = sp` before it moves `sp`, so the depth at the `save` is 0: the frame pointer is the entry SP itself,
 * nowhere near the convention's stack-parameter offset.
 *
 * Only a copy of SP into the architecture's frame register ([ghistabs.parse.frameRegister]) counts; a
 * program whose [ghistabs.parse.dbxArch] is unknown keeps the convention-derived bias.
 */
fun Function.frameBias(monitor: TaskMonitor = TaskMonitor.DUMMY): Int = program.framePointer?.let { fp ->
    setsFramePointer(fp)?.let { setsFp ->
        CallDepthChangeInfo(this, AddressSet(entryPoint..setsFp.address), null, monitor)
            .getSPDepth(setsFp.address).takeIf {
                it != Function.INVALID_STACK_DEPTH_CHANGE && it != Function.UNKNOWN_STACK_DEPTH_CHANGE
            }?.let { -it }
    }
} ?: program.baseStackParamOffset

/** The prologue instruction that copies SP into [fp], within its straight run from the entry. */
private fun Function.setsFramePointer(fp: Register) = program.listing
    .getInstructions(entryPoint, true).iterator().asSequence()
    .take(PROLOGUE_SCAN)
    .takeWhile { it.flowType.isFallthrough }
    .firstOrNull { ins ->
        ins.pcode.any { op ->
            op.opcode == PcodeOp.COPY && program.getRegister(op.getInput(0)) == program.stackPointer &&
                program.getRegister(op.output) == fp
        }
    }

/** The stack alignments an x86 frame's local area can be laid to: STACK_BOUNDARY up to a 32-byte local. */
private val FRAME_ALIGNMENTS = listOf(8, 16, 32)

/**
 * How far above their slots gcc >= 4.8 wrote this function's stab frame [offsets], read off the code in [span].
 *
 * Under LRA, dbxout's `eliminate_regs` reads reload's elimination table, last filled by `ira_costs` before
 * any hard register was allocated. `ix86_compute_frame_layout` then saw no callee-saved register, so the
 * soft frame pointer locals count from sat at `align(hfp, A)` below the CFA rather than at
 * `align(hfp + saves, A)`, where `hfp` is the return address and saved frame pointer and `A` the frame's
 * `stack_alignment_needed`. The shift is the difference of the two. The registers pushed after the frame
 * pointer give `saves`, but `A` is in no stab, and a register already live before allocation (4.8/4.9's PIC
 * `%ebx`) was in the stale layout too; so of the shifts those allow, this takes the one that puts most of
 * [offsets] on a frame-pointer displacement the code uses. 0 on a tie, and when nothing is pushed after
 * the frame pointer: then both layouts agree, as they do for every gcc before 4.8.
 */
fun Function.staleFrameShift(offsets: Collection<Int>, span: AddressSetView): Int {
    val fp = program.framePointer ?: return 0
    val setsFp = setsFramePointer(fp) ?: return 0
    val word = program.defaultPointerSize
    val saves = program.listing.getInstructions(setsFp.address, true).iterator().asSequence()
        .drop(1)
        .takeWhile { it.mnemonicString == "PUSH" }
        .count() * word
    if (saves == 0 || offsets.isEmpty()) return 0
    val used = program.listing.getInstructions(span, true).iterator().asSequence()
        .flatMap { it.pcode.asSequence() }
        .filter { it.opcode == PcodeOp.INT_ADD && program.getRegister(it.getInput(0)) == fp }
        .map { it.getInput(1) }
        .filter { it.isConstant }
        .map { (it.offset shl (64 - 8 * it.size) shr (64 - 8 * it.size)).toInt() }
        // Above that, the saves themselves and the epilogue's `lea -saves(%ebp),%esp`.
        .filterTo(mutableSetOf()) { it < -saves }
    val hfp = 2 * word
    fun align(n: Int, a: Int) = (n + a - 1) / a * a
    val shifts = (listOf(word) + FRAME_ALIGNMENTS).flatMap { a ->
        (0..saves step word).map { stale -> align(hfp + saves, a) - align(hfp + stale, a) }
    }.toSortedSet()
    return shifts.maxBy { shift -> offsets.count { it - shift in used } }
}

class LoadedProgram internal constructor(val program: Program, private val consumer: Any) : AutoCloseable {
    override fun close() {
        program.release(consumer)
    }
}

/** Whether some loader that actually targets this file offers a spec carrying [compiler].  */
internal fun File.offersCompilerSpec(compiler: String) = FileByteProvider(this, null, AccessMode.READ).use { provider ->
    provider.allSupportedLoadSpecs().any { (loader, specs) ->
        loader.tier != LoaderTier.UNTARGETED_LOADER &&
            specs.any { it.languageCompilerSpec?.compilerSpecID?.idAsString == compiler }
    }
}

/** [loadProgram] scoped to [func], released even when it throws. */
fun <R> Any.withProgram(
    binary: File,
    compiler: String? = "gcc",
    log: MessageLog? = null,
    monitor: TaskMonitor? = null,
    func: (Program) -> R,
): R = loadProgram(binary, compiler, log, monitor).use { func(it.program) }
