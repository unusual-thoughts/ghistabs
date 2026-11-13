package ghicpp.recover

import ghicpp.ClassNaming
import ghicpp.abi.generic.PlainVtableParser
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.ByteDataType
import ghidra.program.model.data.DWordDataType
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.DummySink
import ghidrakt.runTransaction
import ghidrakt.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no RTTI: two constructors each storing a table of pointers to functions into `this`, a third
 * nothing disassembled, a switch jumping through a table into its own body, and a table nothing refers to.
 */
@Tag("integration")
class GenericVftableFinderIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("plain-vtables", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.createMemory(".data", "0x402000", 0x100)

        // mov dword ptr [ecx], 0x402010; ret
        builder.setBytes(CTOR, "c7 01 10 20 40 00 c3")
        // mov dword ptr [ecx], 0x402018; ret
        builder.setBytes(CTOR2, "c7 01 18 20 40 00 c3")
        // jmp dword ptr [eax*4 + 0x402040], to two cases in its own body
        builder.setBytes(SWITCH, "ff 24 85 40 20 40 00 90 c3 90 90 90 c3")
        // mov dword ptr [ecx], 0x402060; ret, which nothing disassembled
        builder.setBytes(UNDISASSEMBLED_CTOR, "c7 01 60 20 40 00 c3")
        // Four virtuals no call reaches, none disassembled.
        for (at in listOf(VF1, VF2, VF3, VF4)) builder.setBytes(at, "c3")

        builder.setBytes(TABLE, "00 11 40 00 10 11 40 00")
        builder.setBytes(TABLE2, "20 11 40 00 78 56 34 12")
        builder.setBytes(UNREFERENCED, "00 11 40 00 10 11 40 00")
        builder.setBytes(JUMP_TABLE, "28 10 40 00 2c 10 40 00")
        builder.setBytes(UNDISASSEMBLED_TABLE, "30 11 40 00")

        for (at in listOf(CTOR, CTOR2, SWITCH)) builder.disassemble(at, 1)
        builder.createMemoryReference(CTOR, TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.createMemoryReference(CTOR2, TABLE2, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.createMemoryReference(SWITCH, JUMP_TABLE, RefType.READ, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            val functions = program.functionManager
            for (at in listOf(CTOR, CTOR2)) {
                functions.createFunction(null, addr(at), AddressSet(addr(at), addr(at).add(6)), SourceType.DEFAULT)
                    .setCallingConvention("__thiscall")
            }
            val switchBody = AddressSet(addr(SWITCH), addr(SWITCH).add(12))
            functions.createFunction(null, addr(SWITCH), switchBody, SourceType.DEFAULT)
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun addr(at: String): Address = builder.addr(at)

    private fun found() = GenericVftableFinder(program).potentialVtables.associate { it.addr to it.slots }

    @Test
    fun `a table code refers to is a vftable to its next referred word, a switch's and an unreferred one none`() {
        found() mustBe mapOf(
            addr(TABLE) to listOf(addr(VF1), addr(VF2)),
            addr(TABLE2) to listOf(addr(VF3)),
        )
    }

    @Test
    fun `a table whose constructor is disassembled since is found then`() {
        builder.disassemble(UNDISASSEMBLED_CTOR, 1)
        builder.createMemoryReference(UNDISASSEMBLED_CTOR, UNDISASSEMBLED_TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        found()[addr(UNDISASSEMBLED_TABLE)] mustBe listOf(addr(VF4))
    }

    @Test
    fun `a slot may be laid as a word, and a table ends at an array laid in it`() {
        builder.applyDataType(TABLE, DWordDataType.dataType)
        found()[addr(TABLE)] mustBe listOf(addr(VF1), addr(VF2))
        builder.withTransaction { program.listing.clearCodeUnits(addr(TABLE), addr(TABLE).add(3), false) }
        builder.applyDataType("0x402014", ArrayDataType(ByteDataType.dataType, 4, 1))
        found()[addr(TABLE)] mustBe listOf(addr(VF1))
    }

    @Test
    fun `a seeded table code then refers into is cut there, the rest seeded on its own`() {
        program.runTransaction("seed") { GenericVftableFinder(program).seed() mustBe 2 }
        // mov dword ptr [ecx], 0x402014; ret
        builder.setBytes(LATE_CTOR, "c7 01 14 20 40 00 c3", true)
        builder.createMemoryReference(LATE_CTOR, "0x402014", RefType.DATA, SourceType.ANALYSIS, 0)
        program.runTransaction("again") { GenericVftableFinder(program).seed() mustBe 1 }
        fun slotsAt(at: String) = program.listing.getDataAt(addr(at)).numComponents
        slotsAt(TABLE) mustBe 1
        slotsAt("0x402014") mustBe 1
        program.symbolTable.getSymbols(addr("0x402014")).map { it.parentNamespace.name } mustBe
            listOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402014")
    }

    @Test
    fun `a seeded table's class gets its slots as virtuals and the function storing it as its constructor`() {
        program.runTransaction("seed") {
            GenericVftableFinder(program).seed() mustBe 2
            ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY)
        }
        val cls = "${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010"
        program.symbolTable.getSymbols(addr(TABLE)).map { "${it.parentNamespace.name}::${it.name}" } mustBe
            listOf("$cls::${ClassNaming.VFTABLE}")

        fun nameAt(at: String) = program.functionManager.getFunctionAt(addr(at))?.let { it.getName(true) }
        nameAt(VF1) mustBe "$cls::vfunction1"
        nameAt(VF2) mustBe "$cls::vfunction2"
        nameAt(CTOR) mustBe "$cls::$cls"
        // Made a function off its slot alone.
        nameAt(VF3) mustBe "${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402018::vfunction1"

        // Run again, it finds the tables it seeded claimed.
        program.runTransaction("again") { GenericVftableFinder(program).seed() mustBe 0 }
    }

    private companion object {
        const val CTOR = "0x401000"
        const val CTOR2 = "0x401010"
        const val SWITCH = "0x401020"
        const val VF1 = "0x401100"
        const val VF2 = "0x401110"
        const val VF3 = "0x401120"
        const val VF4 = "0x401130"
        const val UNDISASSEMBLED_CTOR = "0x401180"
        const val LATE_CTOR = "0x401190"
        const val UNDISASSEMBLED_TABLE = "0x402060"
        const val TABLE = "0x402010"
        const val TABLE2 = "0x402018"
        const val UNREFERENCED = "0x402030"
        const val JUMP_TABLE = "0x402040"
    }
}
