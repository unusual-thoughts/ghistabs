package ghistabs.cpp.recover

import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.listing.Data

/**
 * Each slot target's definition, by the first vftable defining it, so every table pointing at a function
 * shares the one definition, as `RecoverClassesFromRTTIScript` shares an inherited slot's.
 */
internal class SlotDefinitions {
    private val byTarget = mutableMapOf<Address, DataType>()

    operator fun get(target: Address): DataType? = byTarget[target]

    /** Keeps [definition] for [target] unless one came first. */
    fun add(target: Address, definition: DataType) {
        byTarget.putIfAbsent(target, definition)
    }

    /** Keeps the definitions of a vftable laid as [table], by the function each slot points at. */
    fun addLaid(table: Data) {
        for (i in 0 until table.numComponents) {
            val slot = table.getComponent(i)
            val target = slot.value as? Address ?: continue
            val definition = (slot.dataType as? Pointer)?.dataType as? FunctionDefinition ?: continue
            add(target, definition)
        }
    }
}
