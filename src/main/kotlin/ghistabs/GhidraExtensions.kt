@file:Suppress("TooManyFunctions")

package ghistabs

import ghidra.app.cmd.function.CallDepthChangeInfo
import ghidra.app.util.bin.FileByteProvider
import ghidra.app.util.bin.InputStreamByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.LoaderTier
import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.address.*
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.*
import ghidra.program.model.listing.Function
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.pcode.PcodeOp
import ghidra.util.task.TaskMonitor
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

/** How many instructions from the entry a prologue may take to set up its frame pointer. */
private const val PROLOGUE_SCAN = 8

/**
 * How far below the entry SP this function's prologue set the frame pointer that gcc's stab offsets
 * count from. On x86 that is usually the one saved-FP push [Program.baseStackParamOffset] implies, but a
 * realigning `main` (gcc >= 4.1: `lea 4(%esp),%ecx; and $-16,%esp; push -4(%ecx); push %ebp`) sits a copied
 * return address deeper (Ghidra tracks the `and` at depth 0 as no change), and on SPARC `save` makes the
 * frame pointer the entry SP itself, nowhere near the convention's stack-parameter offset.
 */
fun Function.frameBias(): Int {
    val sp = program.compilerSpec.stackPointer
    val setsFp = (program.listing.getInstructions(entryPoint, true) as Iterable<Instruction>).asSequence()
        .take(PROLOGUE_SCAN)
        .firstOrNull { ins ->
            ins.pcode.any { op ->
                op.opcode == PcodeOp.COPY && program.getRegister(op.getInput(0)) == sp &&
                    program.getRegister(op.output)?.let { it != sp } == true
            }
        } ?: return program.baseStackParamOffset
    val depth = CallDepthChangeInfo(this, AddressSet(entryPoint, setsFp.address), null, TaskMonitor.DUMMY)
        .getSPDepth(setsFp.address)
    return if (depth == Function.INVALID_STACK_DEPTH_CHANGE || depth == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
        program.baseStackParamOffset
    } else {
        -depth
    }
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
