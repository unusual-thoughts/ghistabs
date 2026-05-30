package ghistabs.builder

import ghidra.program.model.data.Structure

/**
 * Adapter: convert a Ghidra Structure to a list of ComponentRecords for use by pure algorithms.
 * This is integration-tested only (Kind 2), never unit-tested.
 */
fun Structure.toComponentRecords(): List<ComponentRecord> =
    components.map { component ->
        ComponentRecord(
            offsetBytes = component.offset,
            lengthBytes = component.length,
            fieldName = component.fieldName,
            dtPathName = component.dataType.pathName,
            isBitfield = component.isBitFieldComponent,
        )
    }
