package ghistabs.integration

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.loadProgram
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

/**
 * gcc 3.4.5 keeps a `long long` local in two registers but its `:r` stab names only the low one. libgcc's
 * `__udivdi3` returns its 8-byte `ww` as `mov -0x14(%ebp),%edx; mov %ecx,%eax`, and both of `ww`'s stabs
 * say EAX. The local is the pair, high word first.
 */
@Tag("integration")
class RegisterPairIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource("ww, EDX EAX", "ww_1, EDX EAX")
    fun `a two-word register local spans the register after the one its stab names`(local: String, pair: String) {
        val fixture = "xmltest_gcc345.exe"
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        program.defaultContext().importAndAnalyze()

        val udivdi3 = checkNotNull(program.functionManager.getFunctions(true).firstOrNull { it.name == "__udivdi3" })
        val variable = checkNotNull(udivdi3.localVariables.firstOrNull { it.name == local }) { "no local $local" }
        variable.variableStorage.registers.joinToString(" ") { it.name } mustBe pair
        variable.length mustBe 8
    }
}
