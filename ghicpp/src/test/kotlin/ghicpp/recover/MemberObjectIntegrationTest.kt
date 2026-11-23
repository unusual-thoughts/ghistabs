package ghicpp.recover

import ghicpp.MemberAttrs
import ghicpp.MemberAttrs.Companion.memberAttrs
import ghicpp.StructorRole
import ghicpp.abi.generic.PlainVtableParser
import ghicpp.classStruct
import ghicpp.isFlatOwn
import ghicpp.dissect.ThisFunctionDissector
import ghicpp.stubClassStruct
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.listing.VariableUtilities
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.CapturingSink
import ghidrakt.diagnose.DummySink
import ghidrakt.test.mustBe
import ghidrakt.test.mustBeTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * An x86 program with no RTTI: a constructor storing its class's table, which builds a member with no vtable at
 * `this` + 8, whose constructor stores two words, calls a method on that member, and zeroes four words from
 * `this` + 0x10 with `rep stosd`. Where chained, that method calls a helper on its own `this`.
 */
@Tag("integration")
class MemberObjectIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program: Program get() = builder.program

    /**
     * Builds the program, with [afterMember] the 8 bytes of the constructor after it builds the member, and, where
     * [chained], the member's method calling [HELPER] on its own `this`.
     */
    private fun build(afterMember: String = CALL_MEMBER_METHOD, chained: Boolean = false) {
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
        // mov eax, ecx; mov dword ptr [eax+4], 1; (mov ecx, eax; call HELPER;) ret
        builder.setBytes(
            MEMBER_METHOD,
            "8b c1 c7 40 04 01 00 00 00" + (if (chained) " 8b c8 e8 10 00 00 00" else "") + " c3",
        )
        // mov eax, ecx; mov dword ptr [eax], 2; ret
        if (chained) builder.setBytes(HELPER, "8b c1 c7 00 02 00 00 00 c3")
        builder.setBytes(VF1, "c3")
        builder.setBytes(TABLE, "00 11 40 00")

        builder.disassemble(CTOR, 0x2b)
        builder.disassemble(MEMBER_CTOR, 0x10)
        val methodLength = if (chained) 0x11 else 0x0a
        builder.disassemble(MEMBER_METHOD, methodLength)
        if (chained) builder.disassemble(HELPER, 0x09)
        builder.createMemoryReference(TABLE_STORE, TABLE, RefType.DATA, SourceType.ANALYSIS, 0)
        builder.withTransaction {
            val bodies = listOf(CTOR to 0x2b, MEMBER_CTOR to 0x10, MEMBER_METHOD to methodLength) +
                (if (chained) listOf(HELPER to 0x09) else emptyList())
            for ((at, length) in bodies) {
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
        // Nothing else in it, its own fields go in it as they are, no `_data` struct around them.
        structOf(member).definedComponents.map { "+${it.offset} ${it.fieldName} (${it.comment})" } mustBe
            listOf("+0 field_0x0 (own field)", "+4 field_0x4 (own field)")
        structOf(member).isFlatOwn().mustBeTrue()
        program.memberAttrs(addr(MEMBER_CTOR)) mustBe
            MemberAttrs(source = SourceType.ANALYSIS, structor = StructorRole.CONSTRUCTOR)

        val holder = structOf("${GenericVftableFinder.SEEDED_CLASS_PREFIX}00402010")
        holder.getComponentAt(8).dataType.name mustBe member

        // What the holder's constructor calls next on the member is the member's method.
        program.runTransaction("guess") { MethodClassPass(program, DummySink).run(TaskMonitor.DUMMY).moved mustBe 1 }
        program.functionManager.getFunctionAt(addr(MEMBER_METHOD)).parentNamespace.name mustBe member
    }

    @Test
    fun `what a function calls on an object it built on its stack is that object's class's`() {
        build()
        builder.setBytes(
            STACK_CALLER,
            "83 ec 10 8d 0c 24" + // sub esp, 0x10; lea ecx, [esp]
                " e8 f5 fe ff ff" + // call MEMBER_CTOR
                " 8d 0c 24 e8 4d ff ff ff" + // lea ecx, [esp]; call LOCAL_METHOD
                " 83 c4 10 c3", // add esp, 0x10; ret
        )
        // mov eax, ecx; mov dword ptr [eax+4], 2; ret
        builder.setBytes(LOCAL_METHOD, "8b c1 c7 40 04 02 00 00 00 c3")
        builder.disassemble(STACK_CALLER, 0x17)
        builder.disassemble(LOCAL_METHOD, 0x0a)
        builder.withTransaction {
            val functions = program.functionManager
            for ((at, length, convention) in listOf(
                Triple(STACK_CALLER, 0x17, "__cdecl"),
                Triple(LOCAL_METHOD, 0x0a, "__thiscall"),
            )) {
                val body = AddressSet(addr(at), addr(at).add(length - 1L))
                val func = functions.getFunctionAt(addr(at))
                    ?: functions.createFunction(null, addr(at), body, SourceType.DEFAULT)
                func.setCallingConvention(convention)
            }
        }
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, DummySink).run(found) mustBe 1
        }
        program.runTransaction("guess") { MethodClassPass(program, DummySink).run(TaskMonitor.DUMMY).moved mustBe 2 }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        program.functionManager.getFunctionAt(addr(LOCAL_METHOD)).parentNamespace.name mustBe member
    }

    @Test
    fun `a member's class has one struct, the one Ghidra types this with`() {
        build()
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, DummySink).run(found) mustBe 1
        }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        val ns = program.symbolTable.getClassSymbol(member, program.globalNamespace).`object` as GhidraClass
        val structs = program.dataTypeManager.allStructures.asSequence().filter { it.name == member }
        structs.map { it.pathName }.toList() mustBe listOf(structOf(member).pathName)
        VariableUtilities.findOrCreateClassStruct(ns, program.dataTypeManager) mustBe structOf(member)
        val ctor = program.functionManager.getFunctionAt(addr(MEMBER_CTOR))
        (ctor.getParameter(0).dataType as Pointer).dataType mustBe structOf(member)
    }

    @Test
    fun `an empty placeholder Ghidra made for a class gives way to the class's struct`() {
        build()
        val dtm = program.dataTypeManager
        val ns = program.runTransaction("placeholder") {
            val ns = program.symbolTable.createClass(program.globalNamespace, "Placed", SourceType.ANALYSIS)
            dtm.addDataType(
                StructureDataType(CategoryPath.ROOT, "Placed", 0).apply { description = "PlaceHolder Class Structure" },
                null,
            )
            program.stubClassStruct(ns)
            ns
        }
        dtm.allStructures.asSequence().filter { it.name == "Placed" }.map { it.pathName }.toList() mustBe
            listOf("/ClassDataTypes/Placed/Placed")
        VariableUtilities.findExistingClassStruct(ns, dtm) mustBe program.classStruct(ns)
    }

    @Test
    fun `a method called on a guessed method's this is guessed too where guesses are trusted`() {
        build(chained = true)
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, DummySink).run(found) mustBe 1
        }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        // Untrusted, the member's method is guessed off its holder's constructor, the helper off nothing.
        program.runTransaction("guess") { MethodClassPass(program, DummySink).run(TaskMonitor.DUMMY).moved mustBe 1 }
        program.functionManager.getFunctionAt(addr(HELPER)).parentNamespace.isGlobal mustBe true
        program.memberAttrs(addr(MEMBER_METHOD)) mustBe MemberAttrs(source = SourceType.DEFAULT)
        // Trusted, the method's guess is evidence, from this run's guesses or, as here, an earlier run's.
        program.runTransaction("trust") {
            // Its first round moves the helper, off the earlier run's guess.
            MethodClassPass(program, DummySink, trustGuesses = true).run(TaskMonitor.DUMMY) mustBe
                MethodClassResult(listOf(1))
        }
        program.functionManager.getFunctionAt(addr(HELPER)).parentNamespace.name mustBe member
    }

    @Test
    fun `guesses trusted from the start chain within one run`() {
        build(chained = true)
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, DummySink).run(found) mustBe 1
            val result = MethodClassPass(program, DummySink, trustGuesses = true).run(TaskMonitor.DUMMY)
            result.perRound mustBe listOf(1, 1)
            result.offGuesses mustBe 1
            result.toString() mustBe "2 method class(es) guessed in 2 round(s), 1 of them off earlier guesses"
        }
        val member = "${MemberObjectPass.NON_POLYMORPHIC_PREFIX}00401080"
        program.functionManager.getFunctionAt(addr(MEMBER_METHOD)).parentNamespace.name mustBe member
        program.functionManager.getFunctionAt(addr(HELPER)).parentNamespace.name mustBe member
    }

    @Test
    fun `a member's constructor Ghidra took for a __fastcall becomes the __thiscall it is`() {
        build()
        // Ghidra calls a function whose only argument comes in ECX a `__fastcall`.
        program.runTransaction("fastcall") {
            program.functionManager.getFunctionAt(addr(MEMBER_CTOR)).setCallingConvention("__fastcall")
        }
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            val found = ClassPass(program, PlainVtableParser(program), DummySink).run(TaskMonitor.DUMMY).found!!
            MemberObjectPass(program, DummySink).run(found) mustBe 1
        }
        program.functionManager.getFunctionAt(addr(MEMBER_CTOR)).callingConventionName mustBe "__thiscall"
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

    @Test
    fun `the class pass reads the storer the parser read, nothing having changed it between`() {
        build()
        val sink = CapturingSink()
        program.runTransaction("recover") {
            GenericVftableFinder(program).seed() mustBe 1
            ClassPass(program, PlainVtableParser(program), sink).run(TaskMonitor.DUMMY)
        }
        sink.lines.filter { it.tag == "dissection-stale" } mustBe emptyList()
    }

    @Test
    fun `a dissection read before the program changed is read again`() {
        build()
        val sink = CapturingSink()
        val ctor = program.functionManager.getFunctionAt(addr(CTOR))
        val dissector = ThisFunctionDissector(program, emptyList(), sink)
        dissector.readCalls(listOf(ctor), TaskMonitor.DUMMY)
        dissector.readCalls(listOf(ctor), TaskMonitor.DUMMY)
        sink.lines.filter { it.tag == "dissection-stale" } mustBe emptyList()

        // Any change to the program, here a new label, may change what the decompiler makes of the function.
        builder.createLabel(MEMBER_CTOR, "member_ctor")
        dissector.readCalls(listOf(ctor), TaskMonitor.DUMMY).objectCalls.keys mustBe setOf(ctor)
        sink.lines.single { it.tag == "dissection-stale" }.msg mustBe "1 read before the program changed"
    }

    private companion object {
        /** lea ecx, [esi+8]; call MEMBER_METHOD */
        const val CALL_MEMBER_METHOD = "8d 4e 08 e8 8c 00 00 00"

        const val CTOR = "0x401000"
        const val TABLE_STORE = "0x401014"
        const val MEMBER_CTOR = "0x401080"
        const val MEMBER_METHOD = "0x4010a0"
        const val HELPER = "0x4010c0"
        const val LOCAL_METHOD = "0x4010e0"
        const val VF1 = "0x401100"
        const val STACK_CALLER = "0x401180"
        const val TABLE = "0x402010"
    }
}
