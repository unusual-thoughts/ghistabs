package ghistabs.integration

import ghidra.app.decompiler.DecompInterface
import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.database.SpecExtension
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.FunctionSignature
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.HighFunctionDBUtil
import ghidra.program.model.pcode.PcodeOp
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.entrypoints.CALL_BOOKMARK
import ghistabs.entrypoints.DEFERRED_POP_ANALYZER_NAME
import ghistabs.entrypoints.DeferredPopAnalyzer
import ghistabs.entrypoints.MERGE_BOOKMARK
import ghistabs.entrypoints.UNFIXED_BOOKMARK
import ghistabs.entrypoints.endStatePropagator
import ghistabs.runTransaction
import ghistabs.test.mustBe
import ghistabs.test.mustNot
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Two copies of one function, differing only in whether the first call's argument is popped:
 *
 * ```
 *   push ebp / mov ebp,esp / sub esp,0x18
 *   test eax,eax / je merge
 *   push 1 / call g            ; DEFERRED leaves the 4 bytes pushed, BALANCED does `add esp,4`
 * merge:
 *   push 2 / call g            ; ESP is read past the merge
 *   leave / ret
 * ```
 *
 * In [DEFERRED] the two paths reach `merge` with ESP 4 apart, which is gcc's deferred pop in its
 * smallest form, and the decompiler turns `push 2` into a store through a pointer.
 */
@Tag("integration")
class DeferredPopAnalyzerIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("deferredpop", ProgramBuilder._X86, "gcc", this)
        builder.createMemory(".text", "0x400000", 0x100)
        listOf(DEFERRED to DEFERRED_BYTES, CALLEE to "c3", BALANCED to BALANCED_BYTES).forEach { (at, bytes) ->
            builder.setBytes(at, bytes, true)
            builder.createFunction(at)
        }
        // ProgramBuilder's transactions run ambient auto-analysis, this analyzer included: rewind it.
        program.runTransaction("rewind ambient analysis") {
            listOf(DEFERRED, BALANCED).forEach { at ->
                HighFunction.findOverrideSpace(function(at))?.let { space ->
                    program.symbolTable.getSymbols(space).forEach { it.delete() }
                }
            }
            SpecExtension(program).run {
                SpecExtension.getCompilerSpecExtensions(program)
                    .forEach { removeCompilerSpecExtension(it.first, TaskMonitor.DUMMY) }
            }
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    /** The premise: left alone, the decompiler loses ESP at the merge and stores `push 2` through a pointer. */
    @Test
    fun mismatchedMergeDecaysIntoStores() {
        stores(DEFERRED).mustNot("the fixture no longer reproduces the mismatch") { this == 0 }
        stores(BALANCED) mustBe 0
    }

    @Test
    fun deadArgumentsArePoppedAtTheirCall() {
        assumeTrue(endStatePropagator(program) != null, "ESP at each instruction's end needs Ghidra 11.4")
        runAnalyzer()
        overrides(DEFERRED).mapValues { it.value.callingConventionName } mustBe mapOf(FIRST_CALL to "__cdecl_pop4")
        stores(DEFERRED) mustBe 0
        bookmarks(CALL_BOOKMARK).keys mustBe setOf(FIRST_CALL)
        bookmarks(CALL_BOOKMARK).getValue(FIRST_CALL).mustNot("names the merge it evens out") { MERGE !in this }
        bookmarks(MERGE_BOOKMARK).keys mustBe setOf(MERGE)
        bookmarks(MERGE_BOOKMARK).getValue(MERGE).mustNot("names the call that pops") { FIRST_CALL !in this }
        bookmarks(UNFIXED_BOOKMARK) mustBe emptyMap()
    }

    private fun bookmarks(category: String) = program.bookmarkManager.bookmarksIterator.asSequence()
        .filter { it.category == category }
        .associate { it.address.toString() to it.comment }

    @Test
    fun balancedFunctionsAreLeftAlone() {
        runAnalyzer()
        overrides(BALANCED) mustBe emptyMap()
        listOf(CALL_BOOKMARK, MERGE_BOOKMARK, UNFIXED_BOOKMARK).flatMap { bookmarks(it).keys }
            .filter { it >= BALANCED.removePrefix("0x").padStart(8, '0') } mustBe emptyList()
    }

    @Test
    fun rerunIsIdempotent() {
        runAnalyzer()
        val before = overrides(DEFERRED).mapValues { it.value.callingConventionName }
        runAnalyzer()
        overrides(DEFERRED).mapValues { it.value.callingConventionName } mustBe before
    }

    private fun runAnalyzer() = program.runTransaction(DEFERRED_POP_ANALYZER_NAME) {
        DeferredPopAnalyzer().added(
            program,
            program.memory.loadedAndInitializedAddressSet,
            TaskMonitor.DUMMY,
            MessageLog(),
        )
    }

    private fun overrides(at: String) = HighFunction.findOverrideSpace(function(at))?.let { space ->
        program.symbolTable.getSymbols(space).associate {
            it.address.toString() to (HighFunctionDBUtil.readOverride(it)!!.dataType as FunctionSignature)
        }
    } ?: emptyMap()

    private fun stores(at: String): Int {
        val decomp = DecompInterface().also { it.openProgram(program) }
        try {
            val high = decomp.decompileFunction(function(at), 60, TaskMonitor.DUMMY).highFunction
            return high.pcodeOps.asSequence().count { it.opcode == PcodeOp.STORE }
        } finally {
            decomp.dispose()
        }
    }

    private fun function(at: String): Function = program.functionManager.getFunctionAt(builder.addr(at))

    private companion object {
        const val DEFERRED = "0x400000"
        const val CALLEE = "0x400020"
        const val BALANCED = "0x400030"
        const val FIRST_CALL = "0040000c"
        const val MERGE = "00400011"

        // push ebp / mov ebp,esp / sub esp,0x18 / test eax,eax
        const val PROLOGUE = "55 89 e5 83 ec 18 85 c0"
        const val DEFERRED_BYTES = "$PROLOGUE 74 07 6a 01 e8 0f 00 00 00 6a 02 e8 08 00 00 00 c9 c3"
        const val BALANCED_BYTES = "$PROLOGUE 74 0a 6a 01 e8 df ff ff ff 83 c4 04 6a 02 e8 d5 ff ff ff c9 c3"
    }
}
