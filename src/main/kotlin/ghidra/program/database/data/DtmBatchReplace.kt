package ghidra.program.database.data

import ghidra.program.model.data.DataType

/**
 * Batched [DataTypeManagerDB.replaceDataType]. The public API flushes a whole-program reference sweep
 * (`replaceDataTypesUsed`) on **every** call — O(replacements × program).  Ghidra already has the batched
 * machinery (queue all → one `replaceQueuedDataTypes` sweep) but only `remove(List)` exposes it. This lives in Ghidra's
 * package so it can reach the `protected` [DataTypeManagerDB.addDataTypeToReplace]: queue every pair
 * but the last, then let one public `replaceDataType` drain the whole queue in a single sweep.
 *
 * Skips pairs the public path would reject anyway (missing stub, self-replace, dependency cycle,
 * invalid replacement) so the final flush can't throw mid-batch.
 */
fun DataTypeManagerDB.replaceDataTypesBatched(pairs: List<Pair<DataType, DataType>>) {
    val valid = pairs.filter { (old, new) ->
        old !== new &&
            contains(old) &&
            !new.dependsOn(old) &&
            runCatching { DataTypeUtilities.checkValidReplacement(old, new) }.isSuccess
    }
    if (valid.isEmpty()) return
    valid.dropLast(1).forEach { (old, new) -> addDataTypeToReplace(old, new) }
    valid.last().let { (old, new) -> replaceDataType(old, new, false) }
}
