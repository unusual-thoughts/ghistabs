package ghistabs

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.bin.InputStreamByteProvider
import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.DemanglerOptions
import ghidra.app.util.demangler.MangledContext
import ghidra.app.util.demangler.gnu.GnuDemangler
import ghidra.app.util.demangler.gnu.GnuDemanglerOptions
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.DataUtilities
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Listing
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.Memory
import ghidra.program.model.mem.MemoryBlock
import ghidra.util.task.TaskMonitor

/**
 * `currentAddress+10` returns a new Address
 */
operator fun Address.plus(rhs: Long): Address = this.addNoWrap(rhs)

operator fun Address.plus(rhs: Int): Address = this.addNoWrap(rhs.toLong())

/**
 * `currentAddress-10` returns a new Address
 */
operator fun Address.minus(rhs: Long): Address = this.subtractNoWrap(rhs)

operator fun Address.minus(rhs: Int): Address = this.subtractNoWrap(rhs.toLong())

operator fun Address.minus(rhs: Address): Long = this.subtract(rhs)

/**
 * `currentAddress..otherAddress` gives an AddressRange with currentAddress as start, and otherAddress as end
 */
operator fun Address.rangeTo(rhs: Address): AddressRange = AddressRangeImpl(this, rhs)

/**
 * For a Data object that supports component (like arrays or structs) you can use
 * `data[i]` instead of `data.getComponent(i)`
 */
operator fun Data.get(i: Int): Data? = this.getComponent(i)

/**
 * For a Data object that represents a struct you can use `data[fieldName]`
 */
operator fun Data.get(name: String): Data? {
    if (this.dataType is Structure) {
        val s = (this.dataType as Structure)
        val idx = s.components.firstOrNull { it.fieldName == name }?.ordinal
        return idx?.let(this::getComponent)
    }
    return null
}

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
val demangler by lazy { GnuDemangler() }

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
 * Apply Ghidra's demangler to the symbol at [addr] (rename + namespace). Signature / calling-
 * convention / disassembly application are off by default — the stab carries richer types than the
 * mangled name. Returns whether the command applied.
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

/** Clear any instructions covering [addr]..+[length]; true if there were any. An unsized [length]
 *  (a `Dynamic` type that would not resolve) clears nothing rather than guess a span. */
fun Listing.clearAnyDisassembly(addr: Address, length: Int): Boolean {
    if (length <= 0 || getInstructionContaining(addr) == null) return false
    clearCodeUnits(addr, addr + (length - 1), false)
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
    if (listing.clearAnyDisassembly(addr, length)) onClearedCode()
    return DataUtilities.createData(this, addr, dt, length, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
}

val MemoryBlock.byteProvider get() = InputStreamByteProvider(data, size)

fun Memory.getBlockContaining(addr: Address) = blocks.find { it.addressRange.contains(addr) }

fun String.nullIfEmpty() = ifEmpty { null }
