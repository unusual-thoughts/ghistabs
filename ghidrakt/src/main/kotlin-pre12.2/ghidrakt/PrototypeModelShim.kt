package ghidrakt

import ghidra.program.model.data.DataType
import ghidra.program.model.lang.PrototypeModel
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.VariableStorage

/**
 * Pre-12.2: the form without `isVarArgs`, which is all there is. 12.2 added the flag and deprecated this one,
 * along with `getArgLocation` and `getReturnLocation`, which callers now spell as this call. From 12.2 the member
 * takes the call, so this one only ever answers for `isVarArgs = false`. Callers reach it through `import ghidrakt.*`.
 */
fun PrototypeModel.getStorageLocations(
    program: Program,
    dataTypes: Array<DataType>,
    addAutoParams: Boolean,
    isVarArgs: Boolean,
): Array<VariableStorage> {
    require(!isVarArgs) { "varargs storage needs Ghidra 12.2" }
    return getStorageLocations(program, dataTypes, addAutoParams)
}
