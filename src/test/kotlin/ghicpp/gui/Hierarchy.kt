package ghicpp.gui

import ghicpp.hierarchy.*
import ghidra.program.model.listing.Program
import ghistabs.parse.StabReader

/** [program]'s classes, told stabs or not as the plugin tells them. */
fun ClassHierarchy.Companion.of(program: Program) = of(program, StabReader.hasStabs(program))
