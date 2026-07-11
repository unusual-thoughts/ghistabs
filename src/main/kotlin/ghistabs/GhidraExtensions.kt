package ghistabs

import ghidra.app.cmd.label.DemanglerCmd
import ghidra.app.util.bin.InputStreamByteProvider
import ghidra.app.util.demangler.DemangledObject
import ghidra.app.util.demangler.DemanglerOptions
import ghidra.app.util.demangler.DemanglerUtil
import ghidra.framework.model.DomainObject
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Program
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

/** Demangle [mangled] to a [DemangledObject], or null if it isn't a mangled name / demangling fails. */
fun Program.demangle(mangled: String, addr: Address? = null): DemangledObject? =
    runCatching { DemanglerUtil.demangle(this, mangled, addr).firstOrNull() }.getOrNull()

/** Human-readable name for [mangled], falling back to [mangled] */
fun Program.demangledName(mangled: String, addr: Address? = null): String =
    demangle(mangled, addr)?.demangledName ?: mangled

/** Parent-namespace chain, root-first, for [mangled] — or null if it has no enclosing namespace. */
fun Program.namespaceChain(mangled: String): List<String>? = demangle(mangled)?.namespace?.let { parent ->
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

val MemoryBlock.byteProvider get() = InputStreamByteProvider(data, size)
fun String.nullIfEmpty() = ifEmpty { null }
