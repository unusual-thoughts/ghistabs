package ghicpp.gui

import ghicpp.ClassRecordSource
import ghicpp.hierarchy.ClassHierarchy
import ghidra.program.model.listing.Program

/** [program]'s classes, told by another class record source or not as the plugin tells them. */
fun ClassHierarchy.Companion.of(program: Program) = of(program, ClassRecordSource.describedElsewhere(program))
