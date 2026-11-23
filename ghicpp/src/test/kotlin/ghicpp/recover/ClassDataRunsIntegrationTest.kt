package ghicpp.recover

import ghicpp.abi.generic.PlainVtableParser
import ghicpp.classStruct
import ghicpp.ownData
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DummySink
import ghidrakt.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no RTTI: a constructor storing its class's table at `this` and, at `this` + 8, the secondary
 * table its group has after it (`offset_to_top` -8), and a word on each side of that second vptr, at +4 and +0xc,
 * so the class's own fields fall in two gaps.
 */
@Tag("integration")
class ClassDataRunsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    @AfterEach
    fun tearDown() {
        if (::builder.isInitialized) builder.dispose()
    }

    private fun build() {
        builder = ProgramBuilder("data-runs", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.createMemory(".data", "0x402000", 0x100)
        builder.setBytes(
            CTOR,
            "56 8b f1" + // push esi; mov esi, ecx
                " c7 06 10 20 40 00" + // mov dword ptr [esi], TABLE
                " c7 46 08 1c 20 40 00" + // mov dword ptr [esi+8], SECOND_TABLE
                " c7 46 04 01 00 00 00" + // mov dword ptr [esi+4], 1
                " c7 46 0c 02 00 00 00" + // mov dword ptr [esi+0xc], 2
                " 8b c6 5e c3", // mov eax, esi; pop esi; ret
        )
        builder.setBytes(VF1, "c3")
        builder.setBytes(VF2, "c3")
        // offset_to_top 0, no rtti, VF1; then offset_to_top -8, no rtti, VF2
        builder.setBytes(GROUP, "00 00 00 00 00 00 00 00 00 11 40 00 f8 ff ff ff 00 00 00 00 10 11 40 00")
        builder.disassemble(CTOR, CTOR_LENGTH)
        builder.createMemoryReference(TABLE_STORE, TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.createMemoryReference(SECOND_TABLE_STORE, SECOND_TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            val at = builder.addr(CTOR)
            program.functionManager.createFunction(
                null,
                at,
                AddressSet(at, at.add(CTOR_LENGTH - 1L)),
                SourceType.DEFAULT,
            ).setCallingConvention("__thiscall")
        }
    }

    private fun structOf(name: String): Structure {
        val ns = program.symbolTable.getClassSymbol(name, program.globalNamespace).`object` as GhidraClass
        return program.classStruct(ns)!!
    }

    @Test
    fun `own fields in several gaps get a data struct each, named for its offset`() {
        build()
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed()
            ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY)
        }
        val cls = "${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010"
        val struct = structOf(cls)
        struct.ownData().map { (at, dt) -> at to dt.name } mustBe
            listOf(4 to "${cls}_data_0x4", 12 to "${cls}_data_0xc")
        listOf(4, 12).map { struct.getComponentAt(it).fieldName } mustBe listOf("_data_0x4", "_data_0xc")
    }

    private companion object {
        const val CTOR = "0x401000"
        const val CTOR_LENGTH = 0x22
        const val TABLE_STORE = "0x401003"
        const val SECOND_TABLE_STORE = "0x401009"
        const val VF1 = "0x401100"
        const val VF2 = "0x401110"
        const val GROUP = "0x402008"
        const val TABLE = "0x402010"
        const val SECOND_TABLE = "0x40201c"
    }
}
