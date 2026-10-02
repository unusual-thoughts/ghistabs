package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.CommentType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.runTransaction
import ghistabs.test.*
import ghistabs.withProgram
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

/**
 * From gcc 4.8, a stab local's offset counts from the frame gcc laid before register allocation, which saved
 * no register after the frame pointer, so it sits above its slot by however much those saves grew the
 * aligned frame. hello's `probe` pushes `%edi %esi %ebx` under gcc 12: `e` is −0xc in the stab and
 * `-0x1c(%ebp)` in the code. gcc 4.9's pushes only `%ebx`, which the 16-byte alignment both layouts share
 * absorbs, so stab and code agree at −0xc. ptrmem's x86-64 `main` pushes `%rbx`: `a` is −0x20 in the stab
 * and `-0x30(%rbp)` in the code. gcc 4.7's `probe` pushes `%ebx` and predates the stale layout.
 *
 * The shift is read off the disassembly, so the import runs inside auto-analysis, as the CLI's does.
 * The scope plate comment spells the stab offset, then the whole bias.
 */
@Tag("integration")
class StaleFrameShiftIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @ParameterizedTest
    @CsvSource(
        "hello_elf_gcc12, probe, e, -32, Stack[-0xc-20]",
        "hello_elf_gcc49, probe, e, -16, Stack[-0xc-4]",
        "hello_elf_gcc47, probe, e, -16, Stack[-0xc-4]",
        "ptrmem_elf64_gcc12, main, a, -56, Stack[-0x20-24]",
    )
    fun `a gcc 4_8+ local sits where the code uses it, not where the stale frame put it`(
        fixture: String,
        function: String,
        local: String,
        offset: Int,
        storage: String,
    ) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        withProgram(File("src/test/resources/binaries/features/$fixture"), log = MessageLog()) { program ->
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            mgr.initializeOptions()
            mgr.reAnalyzeAll(null)
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(TaskMonitor.DUMMY)
                mgr.waitForAnalysis(null, TaskMonitor.DUMMY)
            }

            val func = checkNotNull(program.functionManager.getFunctions(true).firstOrNull { it.name == function })
            val v = checkNotNull(func.localVariables.firstOrNull { it.name == local }) { "$function has no $local" }
            v.stackOffset mustBe offset

            // Up to the next function: `probe`'s catch block, where `e` lives, is a landing pad outside the body.
            val next = program.functionManager.getFunctions(func.entryPoint.next(), true).first().entryPoint
            val span = AddressSet(func.entryPoint, next)
            val row = program.listing.getCommentAddressIterator(CommentType.PLATE, span, true)
                .iterator().asSequence()
                .flatMap { program.listing.getComment(CommentType.PLATE, it).lines() }
                .single { Regex("""\s$local\s""").containsMatchIn(it) }
            storage mustBeIn row.split(Regex("""\s+"""))
        }
    }
}
