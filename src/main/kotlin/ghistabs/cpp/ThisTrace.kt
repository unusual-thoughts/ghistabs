package ghistabs.cpp

import ghidra.program.model.address.Address
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.pcode.Varnode

/** Where `this` comes in: ECX under x86 `__thiscall`, the first argument register elsewhere. */
fun Program.thisStorage(): Address? {
    val model = functionManager.getCallingConvention("__thiscall") ?: compilerSpec.defaultCallingConvention
    return model.getArgLocation(0, null, PointerDataType(dataTypeManager), this).firstVarnode?.address
}

/** A pointer as the value it points into ([root]) and how far past it ([offset]). */
data class PointerInto(val root: Varnode, val offset: Long) {
    /** Whether [root] is the function's incoming `this`, which comes in at [thisStorage]. */
    fun isThis(thisStorage: Address?) = root.isInput && root.address == thisStorage
}

/**
 * Trace a decompiled pointer back through copies, casts and constant adds, and through a phi whose
 * other inputs are all null, as a pointer from `new` checked before its constructor runs is.
 */
fun Varnode.pointerInto(): PointerInto {
    var vn = this
    var offset = 0L
    repeat(MAX_TRACE) {
        val def = vn.def ?: return PointerInto(vn, offset)
        vn = when (def.opcode) {
            PcodeOp.COPY, PcodeOp.CAST -> def.getInput(0)

            PcodeOp.INT_ADD, PcodeOp.PTRSUB -> {
                val by = def.getInput(1).takeIf { it.isConstant } ?: return PointerInto(vn, offset)
                offset += by.offset
                def.getInput(0)
            }

            PcodeOp.PTRADD -> {
                val (index, size) = def.getInput(1) to def.getInput(2)
                if (!index.isConstant || !size.isConstant) return PointerInto(vn, offset)
                offset += index.offset * size.offset
                def.getInput(0)
            }

            PcodeOp.MULTIEQUAL -> def.inputs.filterNot { it.isConstant && it.offset == 0L }.singleOrNull()
                ?: return PointerInto(vn, offset)

            else -> return PointerInto(vn, offset)
        }
    }
    return PointerInto(vn, offset)
}

private const val MAX_TRACE = 16
