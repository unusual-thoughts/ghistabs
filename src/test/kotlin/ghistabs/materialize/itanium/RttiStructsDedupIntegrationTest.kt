package ghistabs.materialize.itanium

import ghidra.program.database.ProgramBuilder
import ghidra.program.model.data.DataUtilities
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.runTransaction
import ghistabs.test.mustBeEmpty
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * gcc 3.4.5 emits each `_ZTI` typeinfo global as a per-CU COMDAT, so the same RttiStructs layout is
 * applied to that address dozens of times. Because the layout carries an auto-named PointerTypedef
 * field that never compares isEquivalent to its own resolved form, handing the unresolved template
 * to createData forked a `ClassTypeInfoStructure.conflict` on every reapply. RttiStructs now resolves
 * each layout into the DTM once and hands out the resolved, DTM-resident type.
 */
@Tag("integration")
class RttiStructsDedupIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun reapplyingTypeinfoLayoutDoesNotForkConflicts() {
        val builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".data", "0x401000", 0x400)
        val program = builder.program
        val dtm = program.dataTypeManager
        try {
            program.runTransaction("rtti-dedup") {
                val rtti = Rtti(dtm)
                // Both the plain (PointerTypedef) and Si (nested ClassTypeInfoStructure*) layouts,
                // each applied at several distinct addresses — the COMDAT-duplication pattern.
                for ((slot, name) in listOf(Itanium.CLASS_TYPE_INFO_PSEUDO, Itanium.SI_CLASS_TYPE_INFO_PSEUDO)
                    .withIndex()) {
                    val layout = rtti.typeInfoLayout(name)!!
                    repeat(5) { i ->
                        val addr = program.addressFactory.defaultAddressSpace
                            .getAddress(0x401000L + slot * 0x100 + i * 0x20)
                        DataUtilities.createData(
                            program,
                            addr,
                            layout,
                            layout.length,
                            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                        )
                    }
                }
            }
            val conflicts = dtm.allDataTypes.asSequence()
                .filter { it.name.contains("TypeInfoStructure") && it.name.contains(".conflict") }
                .map { it.pathName }
                .toList()
            conflicts.mustBeEmpty("typeinfo layouts forked conflict types: $conflicts")
        } finally {
            builder.dispose()
        }
    }
}
