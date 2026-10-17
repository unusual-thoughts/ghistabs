package ghistabs.entrypoints

import ghidra.program.model.address.Address
import ghidra.program.model.lang.Register
import ghidra.program.model.listing.Program
import ghidra.program.util.SymbolicPropogator

/** [SymbolicPropogator] records end states from 11.4 on; before it, [DeferredPopAnalyzer] has no ESP to compare. */
internal fun endStatePropagator(program: Program): SymbolicPropogator? = null

internal fun SymbolicPropogator.valueAfter(at: Address, reg: Register): SymbolicPropogator.Value? = null
