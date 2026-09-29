package ghistabs.integration

import ghidra.program.model.listing.CommentType
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.loadProgram
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

/**
 * A stab local's offset counts from `%ebp`, wherever the prologue left it. A realigning `main` (gcc >= 4.1:
 * `lea 4(%esp),%ecx; and $-16,%esp; push -4(%ecx); push %ebp`) leaves it a copied return address deeper
 * than the one push the calling convention implies. `doc` is `-0x80(%ebp)` in both stab and code of the
 * gcc 4.2.1 `main`, `-0x68(%ebp)` in the gcc 3.4.5 one, which does not realign. The scope plate comment
 * keeps the convention's slot and appends how far the realignment moved it.
 */
@Tag("integration")
class FrameBiasIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource("xmltest_gcc421.exe, -136, Stack[-0x84-4]", "xmltest_gcc345.exe, -108, Stack[-0x6c]")
    fun `a local sits at its stab offset from where the prologue left the frame pointer`(
        fixture: String,
        offset: Int,
        storage: String,
    ) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        program.defaultContext().import()

        val main = checkNotNull(program.functionManager.getFunctions(true).firstOrNull { it.name == "main" })
        val doc = checkNotNull(main.localVariables.firstOrNull { it.name == "doc" }) { "main has no local doc" }
        doc.stackOffset mustBe offset

        val plates = program.listing.getCommentAddressIterator(CommentType.PLATE, main.body, true)
        val docRow = plates.iterator().asSequence()
            .flatMap { program.listing.getComment(CommentType.PLATE, it).lines() }
            .single { Regex("""\sdoc\s""").containsMatchIn(it) }
        storage mustBeIn docRow.split(Regex("""\s+"""))
    }
}
