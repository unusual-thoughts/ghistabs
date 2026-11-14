package ghicpp.recover

import ghicpp.MemberAttrs
import ghicpp.MemberAttrs.Companion.memberAttrs
import ghicpp.abi.StructorRole
import ghicpp.abi.generic.PlainVtableParser
import ghicpp.classStruct
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.CapturingSink
import ghidrakt.diagnose.DummySink
import ghidrakt.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no RTTI: a constructor storing its class's table, which builds a member with no vtable at
 * `this` + 8, whose constructor stores two words, calls a method on that member, and zeroes four words from
 * `this` + 0x10 with `rep stosd`.
 */
@Tag("integration")
class MemberObjectIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    /** Builds the program, with [afterMember] the 8 bytes of the constructor after it builds the member. */
    private fun build(afterMember: String = CALL_MEMBER_METHOD) {
        builder = ProgramBuilder("member-objects", ProgramBuilder._X86)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x200), true)
        builder.createMemory(".data", "0x402000", 0x100)

        builder.setBytes(
            CTOR,
            "56 57 8b f1" + // push esi; push edi; mov esi, ecx
                " 8d 4e 08 e8 74 00 00 00" + // lea ecx, [esi+8]; call MEMBER_CTOR
                " $afterMember" +
                " c7 06 10 20 40 00" + // mov dword ptr [esi], TABLE
                " 8d 7e 10 b9 04 00 00 00 33 c0 f3 ab" + // lea edi, [esi+0x10]; mov ecx, 4; xor eax, eax; rep stosd
                " 8b c6 5f 5e c3", // mov eax, esi; pop edi; pop esi; ret
        )
        // mov eax, ecx; mov dword ptr [eax], 0; mov dword ptr [eax+4], 0; ret
        builder.setBytes(MEMBER_CTOR, "8b c1 c7 00 00 00 00 00 c7 40 04 00 00 00 00 c3")
        // mov eax, ecx; mov dword ptr [eax+4], 1; ret
        builder.setBytes(MEMBER_METHOD, "8b c1 c7 40 04 01 00 00 00 c3")
        builder.setBytes(VF1, "c3")
        builder.setBytes(TABLE, "00 11 40 00")

        builder.disassemble(CTOR, 0x2b)
        builder.disassemble(MEMBER_CTOR, 0x10)
        builder.disassemble(MEMBER_METHOD, 0x0a)
        builder.createMemoryReference(TABLE_STORE, TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            for ((at, length) in listOf(CTOR to 0x2b, MEMBER_CTOR to 0x10, MEMBER_METHOD to 0x0a)) {
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
    fun tearDown() {
        if (::builder.isInitialized) builder.dispose()
    }

    private fun addr(at: String): Address = builder.addr(at)

    private fun structOf(name: String): Structure {
        val ns = program.symbolTable.getClassSymbol(name, program.globalNamespace).`object` as GhidraClass
        return program.classStruct(ns)!!
    }

    @Test
    fun `a member a constructor builds at an offset gets a class laid there`() {
        build()
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, DummySink).run(found) mustBe 1
        }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        program.functionManager.getFunctionAt(addr(MEMBER_CTOR)).getName(true) mustBe "$member::$member"
        structOf(member).length mustBe 8
        structOf(member).description mustBe "No vtable: named after its first constructor, at 00401080"
        program.memberAttrs(addr(MEMBER_CTOR)) mustBe
            MemberAttrs(source = SourceType.ANALYSIS, structor = StructorRole.CONSTRUCTOR)

        val holder = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        holder.getComponentAt(8).dataType.name mustBe member

        // What the holder's constructor calls next on the member is the member's method.
        program.runTransaction("guess") { MethodClassPass(program, DummySink).run(TaskMonitor.DUMMY) mustBe 1 }
        program.functionManager.getFunctionAt(addr(MEMBER_METHOD)).parentNamespace.name mustBe member
    }

    @Test
    fun `a member is laid over a plain field its holder's constructor stores inside it`() {
        // mov [esi+4], eax; mov [esi+0xc], eax; nop; nop: the holder's constructor stores a word of its own before
        // the member, so its own fields' struct holds the member's offset, and sets the member's second word itself.
        build(afterMember = "89 46 04 89 46 0c 90 90")
        val sink = CapturingSink()
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), sink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, sink).run(found) mustBe 1
        }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        val holder = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        val own = holder.getComponentAt(4).dataType as Structure
        own.getComponentAt(4).dataType.name mustBe member
        own.getComponentContaining(8).offset mustBe 4
        sink.lines.filter { it.tag == "member-unplaced" } mustBe emptyList()
    }

    @Test
    fun `a member running into its holder's own fields stretches them back to hold it`() {
        // mov dword ptr [esi+0xc], 1; nop: the holder's own fields start inside the member at +8.
        build(afterMember = "c7 46 0c 01 00 00 00 90")
        val sink = CapturingSink()
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), sink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, sink).run(found) mustBe 1
        }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        val holder = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        val own = holder.getComponentAt(8).dataType as Structure
        own.name mustBe "${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010_data"
        own.getComponentAt(0).dataType.name mustBe member
        holder.length mustBe 32
        own.length mustBe 24
        sink.lines.filter { it.tag == "member-unplaced" } mustBe emptyList()
    }

    private companion object {
        /** lea ecx, [esi+8]; call MEMBER_METHOD */
        const val CALL_MEMBER_METHOD = "8d 4e 08 e8 8c 00 00 00"

        const val CTOR = "0x401000"
        const val TABLE_STORE = "0x401014"
        const val MEMBER_CTOR = "0x401080"
        const val MEMBER_METHOD = "0x4010a0"
        const val VF1 = "0x401100"
        const val TABLE = "0x402010"
    }
}
