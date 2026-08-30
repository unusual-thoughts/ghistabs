package ghistabs

import ghidra.app.util.bin.InputStreamByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.*
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Parameter
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.Variable
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor
import java.io.File

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

fun <T> DomainObject.runTransaction(description: String = "Kotlin Lambda Transaction", transaction: () -> T): T =
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

val CodeUnit.range get() = minAddress..maxAddress

/** Clear any instructions covering [range]; true if there were any. An empty [range]
 *  (a `Dynamic` type that would not resolve) clears nothing rather than guess a span. */
fun Listing.clearAnyDisassembly(range: AddressRange): Boolean {
    if (range.length == 0L || getInstructionContaining(range.minAddress) == null) return false
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
 * The *default* convention, not [VariableUtilities.getBaseStackParamOffset]'s per-function answer:
 * x86gcc gives `processEntry` `stackshift="0"` against `__cdecl`'s 4, so asking whichever function a
 * caller had first could shift every stack slot in the program by a pointer. Fallback as Ghidra's,
 * for a convention with no stack ParamEntry to derive an offset from.
 */
val Program.baseStackParamOffset get() = compilerSpec.defaultCallingConvention.run {
    stackParameterOffset?.toInt() ?: stackshift
}

class LoadedProgram internal constructor(val program: Program, private val consumer: Any) : AutoCloseable {
    override fun close() {
        program.release(consumer)
    }
}

/**
 * Imports [binary], hinting the [compiler] spec (null leaves the loader its own preference). The
 * caller owns the result and must [close][LoadedProgram.close] it — prefer [withProgram] when the
 * program's life is a single scope.
 */
fun Any.loadProgram(binary: File, compiler: String? = "gcc", log: MessageLog? = null, monitor: TaskMonitor? = null) =
    ProgramLoader.builder()
        .source(binary)
        .apply {
            if (compiler != null) compiler(compiler)
            if (monitor != null) monitor(monitor)
            if (log != null) log(log)
        }
        .let { builder ->
            builder.load().primary.getDomainObject(this).let { program ->
                program.release(builder)
                LoadedProgram(program, this)
            }
        }

/** [loadProgram] scoped to [func], released even when it throws. */
fun <R> Any.withProgram(
    binary: File,
    compiler: String? = "gcc",
    log: MessageLog? = null,
    monitor: TaskMonitor? = null,
    func: (Program) -> R,
): R = loadProgram(binary, compiler, log, monitor).use {
    func(it.program)
}
