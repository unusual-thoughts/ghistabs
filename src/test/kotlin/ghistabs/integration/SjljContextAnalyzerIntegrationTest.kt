package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.ArrayDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.Structure
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.data.UnsignedIntegerDataType
import ghidra.program.model.data.VoidDataType
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.MessageLogSink
import ghistabs.eh.SjljAbi
import ghistabs.entrypoints.SjljContextAnalyzer
import ghistabs.entrypoints.SjljLsdaAnalyzer
import ghistabs.runTransaction
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * [SjljContextAnalyzer] and [SjljLsdaAnalyzer]'s receiver over a hand-built MinGW function that
 * registers its context the way gcc does: the personality and LSDA stores, the `__builtin_setjmp`
 * setup, `_Unwind_SjLj_Register(&fc)`.
 */
@Tag("integration")
class SjljContextAnalyzerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    private val fn = 0x401000
    private val receiver = 0x401080
    private val register = 0x401600
    private val resume = 0x401610
    private val personality = 0x401800
    private val lsda = 0x402000
    private val zti = 0x403000

    private fun hex(v: Int) = "0x${v.toString(16)}"

    private fun addr(v: Int): Address = program.addressFactory.defaultAddressSpace.getAddress(v.toLong())

    private fun le(v: Int) = byteArrayOf(v.toByte(), (v shr 8).toByte(), (v shr 16).toByte(), (v shr 24).toByte())

    private fun code(vararg b: Int) = b.map { it.toByte() }.toByteArray()

    /** `__builtin_setjmp`'s setup as gcc 3.x emits it, through `&jbuf` in a register. */
    private val setjmpThroughRegister get() =
        code(0x8d, 0x45, 0xe0, 0x8d, 0x55, 0xf8, 0x89, 0x10, 0xba) + le(receiver) +
            code(0x89, 0x50, 0x04, 0x89, 0x60, 0x08)

    /** And as gcc 4.x does, each word straight to its `%ebp` slot. */
    private val setjmpToSlots get() =
        code(0x8d, 0x45, 0xf8, 0x89, 0x45, 0xe0, 0xc7, 0x45, 0xe4) + le(receiver) + code(0x89, 0x65, 0xe8)

    /**
     * `push %ebp; mov %esp,%ebp; sub $0x40,%esp`, the context at -0x40(%ebp): its personality and LSDA,
     * [setjmp], `lea -0x40(%ebp),%eax; push %eax; call register`, a `jmp` past the receiver to `leave; ret`.
     */
    private fun function(setjmp: ByteArray) {
        val head = code(0x55, 0x89, 0xe5, 0x83, 0xec, 0x40) +
            code(0xc7, 0x45, 0xd8) + le(personality) + code(0xc7, 0x45, 0xdc) + le(lsda) + setjmp +
            code(0x8d, 0x45, 0xc0, 0x50, 0xe8)
        val call = fn + head.size + 4
        // Then `jmp` over the receiver to the epilogue, as gcc lays the dispatch inside the function.
        val epilogue = receiver + 3
        val body = head + le(register - call) + code(0xe9) + le(epilogue - (call + 5))
        builder.setBytes(hex(fn), body)
        // The receiver: `mov -0x3c(%ebp),%eax` (the call site), then the epilogue, `leave; ret`.
        builder.setBytes(hex(receiver), code(0x8b, 0x45, 0xc4, 0xc9, 0xc3))
        builder.disassemble(hex(fn), body.size)
        builder.disassemble(hex(epilogue), 2)
        builder.createFunction(hex(fn))
        // Its extent, as a stab's function range gives it: Ghidra's flow takes the far `jmp` for a tail call.
        program.runTransaction("extent") {
            program.functionManager.getFunctionAt(addr(fn)).setBody(
                AddressSet(addr(fn), addr(fn + head.size + 4 + 4)).apply { add(addr(epilogue), addr(epilogue + 1)) },
            )
        }
    }

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("sjlj", ProgramBuilder._X86, "gcc", this)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x1000), true)
        builder.createMemory(".rdata", hex(lsda), 0x2000)
        builder.createEmptyFunction("___gxx_personality_sj0", hex(personality), 1, VoidDataType.dataType)
        builder.createEmptyFunction("__Unwind_SjLj_Register", hex(register), 1, VoidDataType.dataType)
        builder.createEmptyFunction("__Unwind_SjLj_Resume", hex(resume), 1, VoidDataType.dataType)
        builder.setBytes(hex(register), code(0xc3))
        // As the loader leaves a symbol table's functions: named, their signatures no one's.
        program.runTransaction("untyped") {
            listOf(personality, register, resume).forEach {
                program.functionManager.getFunctionAt(addr(it)).signatureSource = SourceType.DEFAULT
            }
        }
        builder.setBytes(
            hex(lsda),
            code(0xff, 0x00, 0x0d, 0x01, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00) + le(zti),
        )
        builder.createLabel(hex(zti), "__ZTI3Foo")
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun runAnalyzers() = program.runTransaction("sjlj") {
        SjljLsdaAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
        SjljContextAnalyzer().added(program, program.memory, TaskMonitor.DUMMY, MessageLog())
    }

    private val fc get() = program.functionManager.getFunctionAt(addr(fn)).stackFrame.stackVariables
        .single { it.name == SjljContextAnalyzer.LOCAL }

    private fun Structure.at(offset: Int) = getComponentAt(offset)

    @Test
    fun typesTheContextAndItsJbuf() {
        function(setjmpThroughRegister)
        runAnalyzers()

        // -0x40(%ebp), one saved %ebp below the entry's stack pointer.
        fc.stackOffset.mustBe(-0x44)
        val dt = fc.dataType.mustBeA<Structure>()
        dt.length.mustBe(SjljAbi.JBUF_OFFSET + 12)
        dt.at(SjljAbi.LSDA_OFFSET)?.fieldName.mustBe("lsda")
        val jbuf = dt.at(SjljAbi.JBUF_OFFSET)?.dataType.mustBeA<Structure>()
        jbuf.components.map { it.fieldName }.mustBe(listOf("frame", "resume", "stack"))
    }

    @Test
    fun labelsAndDisassemblesTheReceiver() {
        function(setjmpThroughRegister)
        runAnalyzers()
        receiverMustBeLaid()
    }

    @Test
    fun findsAReceiverStoredStraightToItsSlot() {
        function(setjmpToSlots)
        runAnalyzers()
        receiverMustBeLaid()
    }

    private fun receiverMustBeLaid() {
        val f = program.functionManager.getFunctionAt(addr(fn))
        program.listing.getInstructionAt(addr(receiver)).mustNotBeNull("the receiver must be disassembled")
        // One label, global so the decompiler names it.
        program.symbolTable.getSymbols(addr(receiver)).map { it.name }.mustBe(listOf("sjlj_dispatch_00401080"))
        f.body.contains(addr(receiver)).mustBe(true)
    }

    @Test
    fun typesTheEntryPoints() {
        function(setjmpThroughRegister)
        runAnalyzers()

        val reg = program.functionManager.getFunctionAt(addr(register))
        val param = reg.parameters.single()
        param.name.mustBe("fc")
        (param.dataType as Pointer).dataType.name.mustBe(SjljAbi.CONTEXT)
        program.functionManager.getFunctionAt(addr(resume)).hasNoReturn().mustBe(true)
        program.functionManager.getFunctionAt(addr(personality)).parameters.map { it.name }
            .mustBe(listOf("version", "actions", "exceptionClass", "ue_header", "context"))
    }

    /** Run again, on the program or on the code a later analyzer changed, it finds nothing left to type. */
    @Test
    fun aSecondRunTypesNothing() {
        function(setjmpThroughRegister)
        runAnalyzers()
        val sink = MessageLogSink(MessageLog())
        program.runTransaction("again") {
            SjljContextAnalyzer.typeAll(program, TaskMonitor.DUMMY, sink).mustBe(0 to 0)
            SjljContextAnalyzer.typeAll(program, TaskMonitor.DUMMY, sink, AddressSet(addr(receiver))).mustBe(0 to 0)
        }
    }

    /** A context its stabs end at `lsda`, as gcc's do: that struct, with the jbuf appended. */
    @Test
    fun extendsTheProgramsOwnContext() {
        val own = program.runTransaction("own context") {
            val dtm = program.dataTypeManager
            val s = StructureDataType(CategoryPath("/unwind-sjlj.c"), SjljAbi.CONTEXT, 0, dtm)
            s.add(PointerDataType(s, dtm), "prev", null)
            s.add(IntegerDataType.dataType, "call_site", null)
            s.add(ArrayDataType(UnsignedIntegerDataType.dataType, 4, 4, dtm), "data", null)
            s.add(PointerDataType(VoidDataType.dataType, dtm), "personality", null)
            s.add(PointerDataType(VoidDataType.dataType, dtm), "lsda", null)
            dtm.resolve(s, DataTypeConflictHandler.DEFAULT_HANDLER)
        }
        function(setjmpThroughRegister)
        runAnalyzers()

        fc.dataType.mustBe(own)
        own.length.mustBe(SjljAbi.JBUF_OFFSET + 12)
    }
}
