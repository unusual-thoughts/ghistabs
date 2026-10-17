package ghistabs.entrypoints

import ghidra.program.model.address.Address
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Program
import ghidra.program.util.SymbolicPropogator

/** Ghidra's constant propagation, recording each instruction's end state as well as its start. */
internal fun endStatePropagator(program: Program): SymbolicPropogator? = SymbolicPropogator(program, true)

internal fun SymbolicPropogator.valueAfter(at: Address, reg: Register): SymbolicPropogator.Value? =
    getEndRegisterValue(at, reg)
