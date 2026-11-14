package ghicpp.recover

import ghicpp.abi.generic.PlainVtableParser
import ghicpp.classStruct
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.Array
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
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no RTTI: a constructor storing its class's table, which builds a member with no vtable at
 * `this` + 8, its constructor storing two words, and zeroes four words from `this` + 0x10 with `rep stosd`.
 */
@Tag("integration")
class FillArraysIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("fill-arrays", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.createMemory(".data", "0x402000", 0x100)

        builder.setBytes(
            CTOR,
            "56 57 8b f1" + // push esi; push edi; mov esi, ecx
                " 8d 4e 08 e8 74 00 00 00" + // lea ecx, [esi+8]; call MEMBER_CTOR
                " c7 06 10 20 40 00" + // mov dword ptr [esi], TABLE
                " 8d 7e 10 b9 04 00 00 00 33 c0 f3 ab" + // lea edi, [esi+0x10]; mov ecx, 4; xor eax, eax; rep stosd
                " 8b c6 5f 5e c3", // mov eax, esi; pop edi; pop esi; ret
        )
        // mov eax, ecx; mov dword ptr [eax], 0; mov dword ptr [eax+4], 0; ret
        builder.setBytes(MEMBER_CTOR, "8b c1 c7 00 00 00 00 00 c7 40 04 00 00 00 00 c3")
        builder.setBytes(VF1, "c3")
        builder.setBytes(TABLE, "00 11 40 00")

        builder.disassemble(CTOR, 0x23)
        builder.disassemble(MEMBER_CTOR, 0x10)
        builder.createMemoryReference(TABLE_STORE, TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            for ((at, length) in listOf(CTOR to 0x23, MEMBER_CTOR to 0x10)) {
                val functions = program.functionManager
                val body = AddressSet(addr(at), addr(at).add(length - 1L))
                val func =
                    functions.getFunctionAt(addr(at))
                        ?: functions.createFunction(null, addr(at), body, SourceType.DEFAULT)
                func.setCallingConvention("__thiscall")
            }
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun addr(at: String): Address = builder.addr(at)

    private fun structOf(name: String): Structure {
        val ns = program.symbolTable.getClassSymbol(name, program.globalNamespace).`object` as GhidraClass
        return program.classStruct(ns)!!
    }

    @Test
    fun `a rep stos fill through this is an array`() {
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY)
        }
        val holder = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        val fill = holder.getComponentContaining(0x10).let { part ->
            (part.dataType as? Structure)?.getComponentAt(0x10 - part.offset) ?: part
        }
        (fill.dataType as Array).let { it.numElements to it.elementLength } mustBe (4 to 4)
    }

    @Test
    fun `without fill arrays the rep stos leaves no array`() {
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed()
            ClassPass(program, PlainVtableParser(program), DummySink).apply { fillArrays = false }
                .run(TaskMonitor.DUMMY)
        }
        val holder = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        val parts = holder.definedComponents.flatMap { c ->
            (c.dataType as? Structure)?.definedComponents?.toList()
                ?: listOf(c)
        }
        parts.none { it.dataType is Array } mustBe true
    }

    private companion object {
        const val CTOR = "0x401000"
        const val TABLE_STORE = "0x40100c"
        const val MEMBER_CTOR = "0x401080"
        const val VF1 = "0x401100"
        const val TABLE = "0x402010"
    }
}
