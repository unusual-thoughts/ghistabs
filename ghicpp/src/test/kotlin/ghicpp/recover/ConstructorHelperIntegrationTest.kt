package ghicpp.recover

import ghicpp.abi.generic.PlainVtableParser
import ghicpp.classStruct
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
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
 * An x86 program with no RTTI: a constructor storing its class's table, then calling a method on `this` that sets
 * up the class's fields, a word at +4 and a `bool` at +0x20, as MSVC builds a class whose constructor calls an
 * `init()` of its own. Ghidra types that method a `__fastcall` taking ECX.
 */
@Tag("integration")
class ConstructorHelperIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("constructor-helpers", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.createMemory(".data", "0x402000", 0x100)
        builder.setBytes(
            CTOR,
            "56 8b f1" + // push esi; mov esi, ecx
                " c7 06 10 20 40 00" + // mov dword ptr [esi], TABLE
                " 8b ce e8 30 00 00 00" + // mov ecx, esi; call HELPER
                " 8b c6 5e c3", // mov eax, esi; pop esi; ret
        )
        // mov dword ptr [ecx+4], 0; mov byte ptr [ecx+0x20], 0; ret
        builder.setBytes(HELPER, "c7 41 04 00 00 00 00 c6 41 20 00 c3")
        builder.setBytes(VF1, "c3")
        builder.setBytes(TABLE, "00 11 40 00")
        val bodies = listOf(CTOR to 0x14, HELPER to 0x0c, VF1 to 1)
        for ((at, length) in bodies) builder.disassemble(at, length)
        builder.createMemoryReference(TABLE_STORE, TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            val functions = program.functionManager
            for ((at, length) in bodies) {
                val body = AddressSet(addr(at), addr(at).add(length - 1L))
                val func = functions.getFunctionAt(addr(at))
                    ?: functions.createFunction(null, addr(at), body, SourceType.DEFAULT)
                func.setCallingConvention("__thiscall")
            }
            functions.getFunctionAt(addr(HELPER)).updateFunction(
                "__fastcall",
                null,
                listOf(ParameterImpl("param_1", PointerDataType(program.dataTypeManager), program)),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true,
                SourceType.ANALYSIS,
            )
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
    fun `what a constructor's method on this stores sizes and fills its class`() {
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY)
        }
        val cls = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        // Pointer-aligned past the `bool` at +0x20.
        cls.length mustBe 0x24
        val data = cls.getComponentAt(4).dataType as Structure
        data.getComponentAt(0).dataType.length mustBe 4
        data.getComponentAt(0x1c).dataType.length mustBe 1
        // The method is no structor: it keeps its name.
        program.functionManager.getFunctionAt(addr(HELPER)).name mustBe "FUN_00401040"
    }

    private companion object {
        const val CTOR = "0x401000"
        const val TABLE_STORE = "0x401003"
        const val HELPER = "0x401040"
        const val VF1 = "0x401100"
        const val TABLE = "0x402010"
    }
}
