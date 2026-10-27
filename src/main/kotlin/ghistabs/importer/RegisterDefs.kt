package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Instruction
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.PcodeOp
import ghistabs.harvest.BlockScope
import ghistabs.harvest.Func
import ghistabs.harvest.LocalSymbol

/**
 * The instruction whose write of [reg] should carry [local]'s name, as an offset from [entry]. A
 * register variable's firstUse is the one def address the decompiler maps it at: the varnode written there
 * takes the symbol, its name lock makes it the name representative of its HighVariable, and so the name
 * covers the whole value (Funcdata::newVarnodeOut, HighVariable::compareName, Funcdata::linkSymbol). A
 * write by COPY or LOAD rarely lives that long — the decompiler propagates the copy, or keeps a load in a
 * temporary — so an arithmetic write wins over a move, one on the declaration's line (its initialiser) over
 * one elsewhere in the [fragments]. `__cxa_end_catch`'s `count:r` loads its value on line 104 and keeps it
 * through a `dec edx`; a setter may reuse a register for `this` ahead of the declaration. A call
 * counts as a write of its return register: `uncaught_exception`'s `globals:r` is EAX from its CALL.
 */
internal fun Func.firstDef(
    program: Program,
    entry: Address,
    local: LocalSymbol,
    fragments: List<BlockScope>,
    reg: Register,
): Int? {
    val declared = lineEntries.sortedBy { it.addr }.zipWithNext()
        .filter { (line, _) -> line.line == local.line && line.source == local.sourceFile }
        .map { (line, next) -> line.addr to next.addr }
    val ranges = fragments.map { it.start to it.endExclusive }
    fun writes(spans: List<Pair<Address, Address>>) = spans
        .filter { (start, end) -> start < end }
        .flatMap { (start, end) -> program.listing.getInstructions(AddressSet(start, end.previous()), true) }
        .mapNotNull { insn ->
            when {
                insn.flowType.isCall && insn.returnsIn(program, reg) -> insn to false

                else -> insn.pcode.lastOrNull { op ->
                    op.output?.let { program.getRegister(it) }?.baseRegister == reg.baseRegister
                }?.let { insn to (it.opcode == PcodeOp.COPY || it.opcode == PcodeOp.LOAD) }
            }
        }
    val candidates = writes(declared) + writes(ranges)
    val def = candidates.firstOrNull { (_, isMove) -> !isMove } ?: candidates.firstOrNull() ?: return null
    return (def.first.address.offset - entry.offset).toInt()
}

/**
 * A call defines its callee's return register at the CALL itself — the decompiler gives the call op that
 * output — though the instruction's own p-code writes nothing there.
 */
internal fun Instruction.returnsIn(program: Program, reg: Register): Boolean {
    val callee = flows.firstOrNull()?.let { program.functionManager.getFunctionAt(it) }
    val storage = callee?.getReturn()?.takeUnless { callee.returnType is VoidDataType }?.variableStorage
        ?: program.compilerSpec.defaultCallingConvention
            ?.getReturnLocation(Undefined4DataType.dataType, program)
    return storage?.registers.orEmpty().any { it.baseRegister == reg.baseRegister }
}
