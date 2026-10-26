package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.loadProgram
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * gcc 3.4.5's block reordering splits a lexical block into address ranges, and `dbxout_block` brackets each
 * range on its own, repeating the block's locals in every one. libgcc's `read_uleb128` emits
 * `shift:r(0,17)` (EBX) and `result:r(8,1)` (ESI) three times over, in blocks at +0x8, +0xe and +0x2e: one
 * variable each, not a `shift_1` and `shift_2` the decompiler declares and never uses. Neither register holds
 * anything else, so each is the function's: one block's copy would leave the value the others name unnamed.
 */
@Tag("integration")
class BlockFragmentLocalIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @Test
    fun `a block's fragments repeat its register locals, not declare new ones`() {
        assumeTrue(Fixtures.accepts("crypto_mi_test_gcc345.exe"), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/crypto_mi_test_gcc345.exe"))
        program.defaultContext().importAndAnalyze()

        val func = checkNotNull(program.functionManager.getFunctionAt(program.addressFactory.getAddress("004753a0")))
        func.localVariables.filter { it.isRegisterVariable }.map { it.name to it.firstUseOffset }.sortedBy { it.first } mustBe
            listOf("result" to 0, "shift" to 0)
    }
}
