package ghistabs

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.bin.InputStreamByteProvider
import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.DemanglerOptions
import ghidra.app.util.demangler.MangledContext
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.demangler.gnu.GnuDemanglerOptions
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.*
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor

operator fun Address.plus(rhs: Long): Address = addNoWrap(rhs)
operator fun Address.plus(rhs: Int): Address = addNoWrap(rhs.toLong())

operator fun Address.minus(rhs: Long): Address = subtractNoWrap(rhs)
operator fun Address.minus(rhs: Int): Address = subtractNoWrap(rhs.toLong())
operator fun Address.minus(rhs: Address): Long = subtract(rhs)

operator fun Address.rangeTo(rhs: Address): AddressRange = AddressRangeImpl(this, rhs)

/** `a..<b`. Built by length rather than by bounds: the two-address constructor swaps what arrives out
 *  of order, so `a..<a` would come back as `[a-1, a]`, while a length of 0 is an empty range that
 *  contains nothing — the honest answer for an exclusive end at or below the start. */
operator fun Address.rangeUntil(rhs: Address): AddressRange = AddressRangeImpl(this, (rhs - this).coerceAtLeast(0))

operator fun AddressSetView.minus(addrs: AddressSetView): AddressSet = subtract(addrs)
operator fun AddressSetView.minus(range: AddressRange): AddressSet = subtract(AddressSet(range))
operator fun AddressSetView.minus(addr: Address): AddressSet = subtract(AddressSet(addr))
operator fun AddressSetView.plus(addrs: AddressSetView): AddressSet = union(addrs)
operator fun AddressSetView.plus(range: AddressRange): AddressSet = union(AddressSet(range))
operator fun AddressSetView.plus(addr: Address): AddressSet = union(AddressSet(addr))

operator fun Data.get(i: Int): Data? = this.getComponent(i)
operator fun Data.get(name: String): Data? =
    (dataType as? Composite)?.components?.firstOrNull { it.fieldName == name }?.ordinal?.let(this::get)

val FunctionManager.functions get() = this.getFunctions(true).asIterable()
val Program.functions get() = this.functionManager.getFunctions(true).asIterable()

/** find a function, if any, such that [addr] falls within its convex hull [entry, body.maxAddress]  */
fun FunctionManager.getFunctionWrapping(addr: Address) = getFunctionContaining(addr)
    ?: getFunctions(addr, false).asIterable().firstOrNull()?.takeIf { addr <= it.body.maxAddress }

/** [addr] falls within the convex hull [entry, body.maxAddress] of a function. */
fun FunctionManager.inHull(addr: Address) = getFunctionWrapping(addr) != null

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

// Ghidra's C++ demangler in one place — the only module that touches DemanglerUtil / DemanglerCmd /
// DemanglerOptions. Pure name-string parsing (namespace/template splitting, mangled classification)
// lives Ghidra-free in `ghistabs.parse` (Names.kt).
private val demangler by lazy { GnuDemangler() }

/** Demangle [mangled] to a [DemangledObject], or null if it isn't a mangled name / demangling fails. */
fun demangle(mangled: String): DemangledObject? = runCatching {
    demangler.demangle(MangledContext(null, GnuDemanglerOptions(), mangled, null))
}.getOrNull()

/** Human-readable name for [mangled], falling back to [mangled] */
fun demangledName(mangled: String): String = demangle(mangled)?.demangledName ?: mangled

/** Parent-namespace chain, root-first, for [mangled] — or null if it has no enclosing namespace. */
fun namespaceChain(mangled: String): List<String>? = demangle(mangled)?.namespace?.let { parent ->
    generateSequence(parent) { it.namespace }.map { it.name }.toList().asReversed()
}

/**
 * Apply Ghidra's demangler to the symbol at [addr] (rename + namespace).
 * Signature / calling-convention / disassembly application are off by default -
 * the stab carries richer types than the mangled name. Returns whether the command applied.
 */
fun Program.applyDemangling(
    addr: Address,
    mangled: String,
    applySignature: Boolean = false,
    applyCallingConvention: Boolean = false,
    doDisassembly: Boolean = false,
    monitor: TaskMonitor = TaskMonitor.DUMMY,
) = DemanglerCmd(
    addr,
    mangled,
    DemanglerOptions().apply {
        setApplySignature(applySignature)
        setApplyCallingConvention(applyCallingConvention)
        setDoDisassembly(doDisassembly)
    },
).run { applyTo(this@applyDemangling, monitor) && result != null }

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
