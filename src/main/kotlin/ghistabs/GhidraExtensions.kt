package ghistabs

import ghidra.framework.model.DomainObject
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.address.AddressRangeImpl
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.FunctionManager
import ghidra.program.model.listing.Program

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
