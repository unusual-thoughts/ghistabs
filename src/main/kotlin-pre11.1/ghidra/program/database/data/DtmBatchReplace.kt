package ghidra.program.database.data

import ghidra.program.model.data.DataType

/** shim that executes the replacements one by one. rethrows the first exception encountered */
fun DataTypeManagerDB.replaceDataTypesBatched(pairs: List<Pair<DataType, DataType>>) {
    val valid = pairs.filter { (old, new) ->
        old !== new && contains(old) && !new.dependsOn(old)
    }
    if (valid.isEmpty()) return
    valid.firstNotNullOfOrNull { (old, new) ->
        runCatching { replaceDataType(old, new, false) }.exceptionOrNull()
    }?.let {
        throw it
    }
}
