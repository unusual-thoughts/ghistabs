package ghistabs.integration

import ghidra.app.util.importer.MessageLog
import ghidra.program.database.ProgramBuilder
import ghidra.program.model.listing.Function
import ghidra.program.model.pcode.HighFunction
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghidrakt.runTransaction
import ghidrakt.test.mustBe
import ghidrakt.test.mustNot
import ghistabs.entrypoints.DeferredPopAnalyzer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * A `windows` program whose one `__thiscall` callee pops its own argument (`ret 4`), with no purge
 * recorded for it:
 *
 * ```
 *   push ebp / mov ebp,esp
 *   test eax,eax / je merge
 *   push 1 / call method       ; method pops the 4 bytes itself
 * merge:
 *   push 2 / call g            ; g is __cdecl, purge 0
 *   leave / ret
 * ```
 *
 * The paths meet with ESP even. Counting the unknown purge as 0 makes them look 4 apart and blames the
 * call to `method`, whose convention can't be made to pop more; the walk gives up on the function instead.
 */
@Tag("integration")
class DeferredPopUnknownPurgeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("unknownpurge", ProgramBuilder._X86, "windows", this)
        builder.createMemory(".text", "0x400000", 0x100)
        listOf(CALLER to CALLER_BYTES, METHOD to "c2 04 00", G to "c3").forEach { (at, bytes) ->
            builder.setBytes(at, bytes, true)
            builder.createFunction(at)
        }
        program.runTransaction("set conventions") {
            function(METHOD).apply {
                setCallingConvention("__thiscall")
                stackPurgeSize = Function.UNKNOWN_STACK_DEPTH_CHANGE
            }
            function(G).apply {
                setCallingConvention("__cdecl")
                stackPurgeSize = 0
            }
            HighFunction.findOverrideSpace(function(CALLER))?.let { space ->
                program.symbolTable.getSymbols(space).forEach { it.delete() }
            }
            // ProgramBuilder's transactions run ambient auto-analysis, this analyzer included: rewind it.
            analyzerBookmarks().forEach { program.bookmarkManager.removeBookmark(it) }
        }
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    @Test
    fun aCallWithUnknownPurgeIsNotBlamed() {
        val log = MessageLog()
        program.runTransaction(DeferredPopAnalyzer.NAME) {
            DeferredPopAnalyzer().added(program, program.memory.loadedAndInitializedAddressSet, TaskMonitor.DUMMY, log)
        }
        log.toString().mustNot("tries no override") { "override" in this }
        val overrides = HighFunction.findOverrideSpace(function(CALLER))?.let { program.symbolTable.getSymbols(it) }
        (overrides?.count() ?: 0) mustBe 0
        analyzerBookmarks().map { it.category } mustBe emptyList()
    }

    private fun analyzerBookmarks() = program.bookmarkManager.bookmarksIterator.asSequence()
        .filter { it.category.startsWith(DeferredPopAnalyzer.NAME) }.toList()

    private fun function(at: String): Function = program.functionManager.getFunctionAt(builder.addr(at))

    private companion object {
        const val CALLER = "0x400000"
        const val METHOD = "0x400020"
        const val G = "0x400030"

        // push ebp / mov ebp,esp / test eax,eax / je +7 / push 1 / call METHOD / push 2 / call G / leave / ret
        const val CALLER_BYTES = "55 89 e5 85 c0 74 07 6a 01 e8 12 00 00 00 6a 02 e8 1b 00 00 00 c9 c3"
    }
}
