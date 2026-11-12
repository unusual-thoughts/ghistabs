package ghicpp.recover

import ghicpp.classStruct
import ghidra.app.decompiler.DecompInterface
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.UnsignedIntegerDataType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.DummySink
import ghidrakt.runTransaction
import ghistabs.test.mustBe
import ghidrakt.useWith
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no RTTI and no constructor of its own: a factory that calls `operator new(0x20)` and, where
 * that returns an object, builds it inline. It stores the base's table, a base field at +8, builds a member with no
 * vtable at +0x10 with that member's constructor, then stores the derived class's table and a field at +0x18.
 */
@Tag("integration")
class InlinedConstructorIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("inlined-constructor", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.createMemory(".data", "0x402000", 0x100)

        builder.setBytes(
            FACTORY,
            "56 6a 20 e8 f8 00 00 00" + // push esi; push 0x20; call NEW
                " 83 c4 04 8b f0 85 f6 74 26" + // add esp, 4; mov esi, eax; test esi, esi; je null
                " c7 06 10 20 40 00" + // mov dword ptr [esi], BASE_TABLE
                " c7 46 08 05 00 00 00" + // mov dword ptr [esi+8], 5
                " 8d 4e 10 e8 5a 00 00 00" + // lea ecx, [esi+0x10]; call MEMBER_CTOR
                " c7 06 20 20 40 00" + // mov dword ptr [esi], DERIVED_TABLE
                " c7 46 18 07 00 00 00" + // mov dword ptr [esi+0x18], 7
                " 8b c6 5e c3" + // mov eax, esi; pop esi; ret
                " 33 c0 5e c3", // null: xor eax, eax; pop esi; ret
        )
        // mov eax, ecx; mov dword ptr [eax], 0; mov dword ptr [eax+4], 0; ret
        builder.setBytes(MEMBER_CTOR, "8b c1 c7 00 00 00 00 00 c7 40 04 00 00 00 00 c3")
        builder.setBytes(NEW, "33 c0 c3")
        for (vf in listOf(BASE_VF, DERIVED_VF1, DERIVED_VF2)) builder.setBytes(vf, "c3")
        builder.setBytes(BASE_TABLE, "80 11 40 00")
        builder.setBytes(DERIVED_TABLE, "90 11 40 00 a0 11 40 00")

        val bodies = listOf(FACTORY to 0x3b, MEMBER_CTOR to 0x10, NEW to 0x03)
        for ((at, length) in bodies) builder.disassemble(at, length)
        builder.createMemoryReference(BASE_STORE, BASE_TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.createMemoryReference(DERIVED_STORE, DERIVED_TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            val functions = program.functionManager
            for ((at, length) in bodies) {
                val body = AddressSet(addr(at), addr(at).add(length - 1L))
                functions.getFunctionAt(addr(at)) ?: functions.createFunction(null, addr(at), body, SourceType.DEFAULT)
            }
            functions.getFunctionAt(addr(MEMBER_CTOR)).setCallingConvention("__thiscall")
            functions.getFunctionAt(addr(NEW)).apply {
                setName("operator_new", SourceType.IMPORTED)
                setCallingConvention("__cdecl")
                val dtm = program.dataTypeManager
                updateFunction(
                    "__cdecl",
                    ReturnParameterImpl(PointerDataType(dtm), program),
                    listOf(ParameterImpl("size", UnsignedIntegerDataType.dataType, program)),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true,
                    SourceType.IMPORTED,
                )
            }
            functions.getFunctionAt(addr(FACTORY)).setCallingConvention("__cdecl")
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
    fun `a constructor inlined after operator new sizes its class and gives it its base, fields and members`() {
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 2
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            found.inlined.single().order.map { it.name } mustBe listOf(BASE, DERIVED)
            MemberObjectPass(program, DummySink).run(found) mustBe 1
        }
        val derived = structOf(DERIVED)
        derived.length mustBe 0x20
        // The base's fields past the vptr the derived class takes over, then the derived class's own.
        derived.getComponentAt(4).comment mustBe "public $BASE"
        derived.getComponentAt(0x18).dataType.length mustBe 4

        val base = structOf(BASE)
        base.getComponentContaining(8).dataType.length mustBe 8

        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        program.functionManager.getFunctionAt(addr(MEMBER_CTOR)).getName(true) mustBe "$member::$member"
        base.getComponentContaining(0x10).dataType.name mustBe member

        // What operator new returns is typed as the class it builds, in the factory that inlines its constructor.
        DecompInterface().useWith(program) { decomp ->
            val factory = program.functionManager.getFunctionAt(addr(FACTORY))
            val c = decomp.decompileFunction(factory, 30, TaskMonitor.DUMMY).decompiledFunction.c
            c.contains("$DERIVED *") mustBe true
        }
    }

    @Test
    fun `with the option off, a constructor inlined after operator new is left alone`() {
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 2
            val pass = ClassPass(program, PlainVtableParser(program), DummySink)
            pass.inlinedConstructors = false
            pass.run(TaskMonitor.DUMMY).found!!.inlined mustBe emptyList()
        }
        (structOf(DERIVED).length < 0x20) mustBe true
    }

    private companion object {
        const val FACTORY = "0x401000"
        const val BASE_STORE = "0x401011"
        const val DERIVED_STORE = "0x401026"
        const val MEMBER_CTOR = "0x401080"
        const val NEW = "0x401100"
        const val BASE_VF = "0x401180"
        const val DERIVED_VF1 = "0x401190"
        const val DERIVED_VF2 = "0x4011a0"
        const val BASE_TABLE = "0x402010"
        const val DERIVED_TABLE = "0x402020"
        val BASE = "${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010"
        val DERIVED = "${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402020"
    }
}
