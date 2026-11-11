package ghistabs.entrypoints

import ghicpp.ClassRecordSource
import ghidra.program.model.listing.Program
import ghistabs.parse.StabReader

/** The stabs import records the classes of a program that has stabs: Tools > Stabs > Re-import makes the record. */
class StabsClassRecordSource : ClassRecordSource {
    override fun describes(program: Program) = StabReader.hasStabs(program)

    override fun missingRecordHint(program: Program) =
        "no stabs record: Tools > Stabs > Re-import to add it".takeIf { StabReader.hasStabs(program) }
}
