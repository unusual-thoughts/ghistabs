package ghicpp.recover

import ghicpp.MemberAttrs
import ghicpp.MemberAttrs.Companion.memberAttrs
import ghicpp.abi.StructorRole
import ghicpp.abi.generic.PlainVtableParser
import ghicpp.classStruct
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.UnsignedIntegerDataType
import ghidra.program.model.listing.Function.FunctionUpdateType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.ParameterImpl
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.ReturnParameterImpl
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.diagnose.CapturingSink
import ghidrakt.runTransaction
import ghidrakt.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no vtable at all: `main` allocates 12 bytes with `operator new` and calls a `__thiscall`
 * function on them, which stores two words through `this`, then allocates [SECOND_SIZE] bytes and calls
 * [SECOND_CALLEE] on them.
 */
@Tag("integration")
class AllocatedObjectIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    private fun build(secondSize: Int = 0x10, secondCallee: String = OTHER) {
        builder = ProgramBuilder("allocated-objects", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.setBytes(
            MAIN,
            "6a 0c e8 f9 00 00 00 83 c4 04" + // push 0xc; call NEW; add esp, 4
                " 8b c8 e8 6f 00 00 00" + // mov ecx, eax; call CTOR
                " 6a %02x e8 e8 00 00 00 83 c4 04".format(secondSize) + // push secondSize; call NEW; add esp, 4
                " 8b c8 e8 ${rel(0x40101d, secondCallee)} c3", // mov ecx, eax; call secondCallee; ret
        )
        // mov eax, ecx; mov dword ptr [eax], 0; mov dword ptr [eax+4], 0; ret
        builder.setBytes(CTOR, "8b c1 c7 00 00 00 00 00 c7 40 04 00 00 00 00 c3")
        // mov eax, ecx; mov dword ptr [eax], 1; ret
        builder.setBytes(OTHER, "8b c1 c7 00 01 00 00 00 c3")
        builder.setBytes(NEW, "33 c0 c3")
        val bodies = listOf(MAIN to 0x23, CTOR to 0x10, OTHER to 0x09, NEW to 0x03)
        for ((at, length) in bodies) builder.disassemble(at, length)
        builder.withTransaction {
            val functions = program.functionManager
            for ((at, length) in bodies) {
                val body = AddressSet(addr(at), addr(at).add(length - 1L))
                functions.getFunctionAt(addr(at)) ?: functions.createFunction(null, addr(at), body, SourceType.DEFAULT)
            }
            functions.getFunctionAt(addr(CTOR)).setCallingConvention("__thiscall")
            functions.getFunctionAt(addr(OTHER)).setCallingConvention("__thiscall")
            functions.getFunctionAt(addr(NEW)).run {
                setName("operator_new", SourceType.USER_DEFINED)
                updateFunction(
                    "__cdecl",
                    ReturnParameterImpl(PointerDataType(), program),
                    listOf(ParameterImpl("size", UnsignedIntegerDataType(), program)),
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true,
                    SourceType.USER_DEFINED,
                )
            }
        }
    }

    @AfterEach
    fun tearDown() {
        if (::builder.isInitialized) builder.dispose()
    }

    private fun addr(at: String): Address = builder.addr(at)

    /** The rel32 of a call at [from], 5 bytes long, to [to], little-endian. */
    private fun rel(from: Long, to: String) = (to.removePrefix("0x").toLong(16) - (from + 5)).let { d ->
        (0 until 4).joinToString(" ") { "%02x".format((d shr (8 * it)) and 0xff) }
    }

    private fun recover(sink: CapturingSink = CapturingSink()): Int {
        var made = 0
        program.runTransaction("recover") {
            val found = ClassPass(program, PlainVtableParser(program), sink).run(TaskMonitor.DUMMY).found!!
            made = MemberObjectPass(program, sink).run(found)
        }
        return made
    }

    private fun classNamed(name: String) =
        program.symbolTable.getClassSymbol(name, program.globalNamespace)?.`object` as? GhidraClass

    @Test
    fun `what operator new allocates gets a class off the first function called on it`() {
        build()
        recover() mustBe 2
        val cls = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        program.functionManager.getFunctionAt(addr(CTOR)).getName(true) mustBe "$cls::$cls"
        program.memberAttrs(addr(CTOR)) mustBe
            MemberAttrs(source = SourceType.ANALYSIS, structor = StructorRole.CONSTRUCTOR)
        // As large as allocated, past the two words its constructor stores.
        program.classStruct(classNamed(cls)!!)!!.length mustBe 12
        program.classStruct(classNamed("${MemberObjectPass.NON_POLYMORPHIC_PREFIX}004010a0")!!)!!.length mustBe 16
    }

    @Test
    fun `a function first called after allocations of different sizes builds no class`() {
        build(secondCallee = CTOR)
        val sink = CapturingSink()
        recover(sink) mustBe 0
        classNamed("${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080") mustBe null
        ("member-allocated-sizes" in sink.lines.map { it.tag }) mustBe true
    }

    @Test
    fun `a function with a name of its own outside a class builds no class`() {
        build()
        program.runTransaction("name") {
            program.functionManager.getFunctionAt(addr(OTHER)).setName("fill", SourceType.USER_DEFINED)
        }
        recover() mustBe 1
        classNamed("${MemberObjectPass.NON_POLYMORPHIC_PREFIX}004010a0") mustBe null
    }

    private companion object {
        const val MAIN = "0x401000"
        const val CTOR = "0x401080"
        const val OTHER = "0x4010a0"
        const val NEW = "0x401100"
    }
}
