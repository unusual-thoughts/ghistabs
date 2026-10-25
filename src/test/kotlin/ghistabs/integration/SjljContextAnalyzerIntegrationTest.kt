package ghistabs.integration

import ghidra.app.cmd.function.CreateFunctionCmd
import ghidra.app.decompiler.DecompInterface
import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.FlowOverride
import ghidra.program.model.symbol.SourceType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.eh.SjljAbi
import ghistabs.cpp.eh.SjljApplier
import ghistabs.diagnose.MessageLogSink
import ghistabs.entrypoints.HullDisassemblyAnalyzer
import ghistabs.entrypoints.SjljContextAnalyzer
import ghistabs.entrypoints.SjljLsdaAnalyzer
import ghistabs.runTransaction
import ghistabs.test.mustBe
import ghistabs.test.mustBeA
import ghistabs.test.mustBeNull
import ghistabs.test.mustNotBeNull
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
    private val thrower = 0x401620
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
     * [setjmp], `lea -0x40(%ebp),%eax; push %eax; call register`, a `jmp` past the receiver to `leave; ret`,
     * after [stores] as gcc's `movl $index, -0x3c(%ebp)` into `fc.call_site`.
     */
    private fun function(setjmp: ByteArray, vararg stores: Int) {
        val head = code(0x55, 0x89, 0xe5, 0x83, 0xec, 0x40) +
            code(0xc7, 0x45, 0xd8) + le(personality) + code(0xc7, 0x45, 0xdc) + le(lsda) + setjmp +
            stores.fold(byteArrayOf()) { acc, i -> acc + code(0xc7, 0x45, 0xc4) + le(i) } +
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
            program.functionManager.getFunctionAt(addr(fn)).body =
                AddressSet(addr(fn), addr(fn + head.size + 4 + 4)).apply { add(addr(epilogue), addr(epilogue + 1)) }
        }
    }

    /**
     * The receiver past a call that turns out not to return, as gcc lays it when the try block ends in
     * a throw: the context and [setjmpToSlots], `call register`, `call thrower`, the `add $0x10,%esp`
     * after it, then the receiver, `mov -0x3c(%ebp),%eax; leave; ret`. Until the thrower is known not
     * to return, the entry falls through to all of it.
     */
    private fun functionWithReceiverPastAThrow() {
        val head = code(0x55, 0x89, 0xe5, 0x83, 0xec, 0x40) +
            code(0xc7, 0x45, 0xd8) + le(personality) + code(0xc7, 0x45, 0xdc) + le(lsda) + setjmpToSlots +
            code(0x8d, 0x45, 0xc0, 0x50, 0xe8)
        val body = head + le(register - (fn + head.size + 4))
        val call = receiver - 8
        builder.setBytes(hex(fn), body + ByteArray(call - fn - body.size) { 0x90.toByte() })
        builder.setBytes(hex(call), code(0xe8) + le(thrower - (call + 5)) + code(0x83, 0xc4, 0x10))
        builder.setBytes(hex(receiver), code(0x8b, 0x45, 0xc4, 0xc9, 0xc3))
        builder.disassemble(hex(fn), receiver + 5 - fn)
        builder.createFunction(hex(fn))
    }

    /**
     * The thrower found not to return, and Ghidra's repair of that as its no-return analysis does it
     * (FindNoReturnFunctionsAnalyzer): no fall-through from the call, the flow past it cleared, the body
     * recomputed.
     */
    private fun repairAfterTheThrow() = program.runTransaction("no-return") {
        program.functionManager.getFunctionAt(addr(thrower)).setNoReturn(true)
        program.listing.getInstructionAt(addr(receiver - 8)).setFlowOverride(FlowOverride.CALL_RETURN)
        ClearFlowAndRepairCmd(AddressSet(addr(receiver - 3)), null, true, false, true)
            .applyTo(program, TaskMonitor.DUMMY)
        val f = program.functionManager.getFunctionAt(addr(fn))
        CreateFunctionCmd.fixupFunctionBody(program, f, TaskMonitor.DUMMY)
    }

    private fun receiverFlow() = program.referenceManager.getReferencesTo(addr(receiver)).iterator().asSequence()
        .filter { it.referenceType.isFlow }.toList()

    /**
     * The receiver and a landing pad past the body's last instruction, as gcc lays them when the code
     * before them ends in a jump back: the pad's `je` skips a call to a non-returning `__throw_ios_failure`
     * and the `add $0x10,%esp` after it, which nothing reaches. Returns that `add`'s address.
     */
    private fun functionWithPadsPastItsBody(): Int {
        val head = code(0x55, 0x89, 0xe5, 0x83, 0xec, 0x40) +
            code(0xc7, 0x45, 0xd8) + le(personality) + code(0xc7, 0x45, 0xdc) + le(lsda) + setjmpToSlots +
            code(0x8d, 0x45, 0xc0, 0x50, 0xe8)
        val epilogue = fn + head.size + 4
        val body = head + le(register - epilogue) + code(0xc9, 0xc3)
        builder.setBytes(hex(fn), body)
        // `test %eax,%eax; je join; call thrower; add $0x10,%esp; join: jmp epilogue`, right before the receiver.
        val pad = receiver - 17
        builder.setBytes(hex(fn + body.size), ByteArray(pad - fn - body.size) { 0x90.toByte() })
        builder.setBytes(
            hex(pad),
            code(0x85, 0xc0, 0x74, 0x08, 0xe8) + le(thrower - (pad + 9)) + code(0x83, 0xc4, 0x10, 0xe9) +
                le(epilogue - (pad + 17)),
        )
        // The receiver: `mov -0x3c(%ebp),%eax; cmp $1,%eax; je pad; push %eax; call resume`.
        builder.setBytes(
            hex(receiver),
            code(0x8b, 0x45, 0xc4, 0x83, 0xf8, 0x01, 0x74, pad - (receiver + 8), 0x50, 0xe8) +
                le(resume - (receiver + 14)),
        )
        builder.disassemble(hex(fn), body.size)
        builder.createFunction(hex(fn))
        return pad + 9
    }

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("sjlj", ProgramBuilder._X86, "gcc", this)
        builder.setExecute(builder.createMemory(".text", "0x401000", 0x1000), true)
        builder.createMemory(".rdata", hex(lsda), 0x2000)
        builder.createEmptyFunction("___gxx_personality_sj0", hex(personality), 1, VoidDataType.dataType)
        builder.createEmptyFunction("__Unwind_SjLj_Register", hex(register), 1, VoidDataType.dataType)
        builder.createEmptyFunction("__Unwind_SjLj_Resume", hex(resume), 1, VoidDataType.dataType)
        builder.createEmptyFunction("__ZSt19__throw_ios_failurePKc", hex(thrower), 1, VoidDataType.dataType)
        builder.setBytes(hex(thrower), code(0xc3))
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
        .single { it.name == SjljApplier.LOCAL }

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

    /** The address-taking instruction flows to the receiver, so a no-return repair keeps it in code and body. */
    @Test
    fun keepsTheReceiverThroughANoReturnRepair() {
        functionWithReceiverPastAThrow()
        runAnalyzers()
        receiverFlow().map { it.fromAddress }.mustBe(listOf(addr(fn + 0x1a)))

        repairAfterTheThrow()
        program.listing.getInstructionAt(addr(receiver - 3)).mustBeNull("the repair clears the dead add")
        program.listing.getInstructionAt(addr(receiver)).mustNotBeNull("the receiver must stay code")
        program.listing.getComment(CommentType.PRE, addr(receiver)).mustNotBeNull()
        program.functionManager.getFunctionAt(addr(fn)).body.contains(addr(receiver + 4)).mustBe(true)
    }

    /** The case the flow reference is for: without it, the same repair clears the receiver. */
    @Test
    fun withoutTheFlowARepairClearsTheReceiver() {
        functionWithReceiverPastAThrow()
        runAnalyzers()
        program.runTransaction("drop flow") { receiverFlow().forEach(program.referenceManager::delete) }

        repairAfterTheThrow()
        program.listing.getInstructionAt(addr(receiver)).mustBeNull("nothing but the flow keeps the receiver")
    }

    /** The flow is no branch the decompiler takes: the function decompiles the same without it. */
    @Test
    fun theFlowLeavesTheDecompilationAlone() {
        function(setjmpToSlots)
        runAnalyzers()
        val with = decompiled()
        receiverFlow().size.mustBe(1)
        program.runTransaction("drop flow") { receiverFlow().forEach(program.referenceManager::delete) }
        decompiled().mustBe(with)
    }

    private fun decompiled(): String {
        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
            val f = program.functionManager.getFunctionAt(addr(fn))
            return decomp.decompileFunction(f, 60, TaskMonitor.DUMMY).decompiledFunction.c
        } finally {
            decomp.dispose()
        }
    }

    /**
     * Pads past the body are the function's too, so the In-Function Gap Disassembler, run again for the
     * changed body, takes the dead `add` after the pad's non-returning call (libstdc++'s
     * `ios_base::_M_grow_words`).
     */
    @Test
    fun takesThePadsPastTheBodyIntoTheFunction() {
        val dead = layPadsPastTheBody()
        val f = program.functionManager.getFunctionAt(addr(fn))
        f.body.contains(addr(receiver)).mustBe(true)
        f.body.contains(addr(receiver - 17)).mustBe(true)
        program.listing.getInstructionAt(addr(dead)).mustBeNull("nothing flows to the dead add")

        runHullAnalyzer()
        program.listing.getInstructionAt(addr(dead)).mustNotBeNull("the dead add inside the pads must be disassembled")
    }

    /**
     * And they stay when Ghidra recomputes the body from the entry, as it does once a call in it turns
     * out not to return: the receiver's flow reference brings them back, with their gap.
     */
    @Test
    fun keepsThePadsPastTheBodyThroughARecompute() {
        val dead = layPadsPastTheBody()
        program.runTransaction("recompute") {
            val f = program.functionManager.getFunctionAt(addr(fn))
            CreateFunctionCmd.fixupFunctionBody(program, f, TaskMonitor.DUMMY)
        }
        program.functionManager.getFunctionAt(addr(fn)).body.contains(addr(receiver - 17)).mustBe(true)

        runHullAnalyzer()
        program.listing.getInstructionAt(addr(dead)).mustNotBeNull("the dead add inside the pads must be disassembled")
    }

    /** [functionWithPadsPastItsBody], its callees known not to return, and the analyzers run. */
    private fun layPadsPastTheBody(): Int {
        val dead = functionWithPadsPastItsBody()
        program.runTransaction("noreturn") {
            listOf(resume, thrower).forEach { program.functionManager.getFunctionAt(addr(it)).setNoReturn(true) }
        }
        runAnalyzers()
        return dead
    }

    private fun runHullAnalyzer() = program.runTransaction("hull") {
        HullDisassemblyAnalyzer().added(program, AddressSet(addr(fn)), TaskMonitor.DUMMY, MessageLog())
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

    /**
     * The LSDA's two call sites, a cleanup and a `catch (Foo)` on landing pads 0 and 1: each
     * `fc.call_site` store but -1's names what its index selects, and the receiver lists the pads.
     */
    @Test
    fun commentsWhatEachCallSiteCatches() {
        function(setjmpThroughRegister, 1, -1, 2, 0)
        runAnalyzers()

        val listing = program.listing
        val comments = listing.getInstructions(program.functionManager.getFunctionAt(addr(fn)).body, true)
            .filter { it.mnemonicString == "MOV" && it.getScalar(1)?.signedValue in -1L..2L }
            .map { listing.getComment(CommentType.PRE, it.address) }
        comments.mustBe(
            listOf(
                "SJLJ call site 1, landing pad 0: cleanup",
                null,
                "SJLJ call site 2, landing pad 1: catch (Foo)",
                "SJLJ call site 0: terminate if anything throws",
            ),
        )
        listing.getComment(CommentType.PRE, addr(receiver))!!.lines().drop(1)
            .mustBe(listOf("landing pad 0: cleanup", "landing pad 1: catch (Foo)"))
    }

    /** Run again, on the program or on the code a later analyzer changed, it finds nothing left to type. */
    @Test
    fun aSecondRunTypesNothing() {
        function(setjmpThroughRegister)
        runAnalyzers()
        val sink = MessageLogSink(MessageLog(), originator = SjljContextAnalyzer.NAME)
        program.runTransaction("again") {
            SjljApplier(program, TaskMonitor.DUMMY, sink).applyAll(program.memory).mustBe(0 to 0)
            SjljApplier(program, TaskMonitor.DUMMY, sink).applyAll(AddressSet(addr(receiver))).mustBe(0 to 0)
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
