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
 * gcc 3.4.5 types each `_ZTI` global with its pseudo struct, a class's and a pointer's alike, and gives
 * none of them a definition. A pointer's typeinfo carries its pointee's after the name (`_ZTIPKc`,
 * `const char*`); a fundamental type's and an enum's only the name (`_ZTIc`).
 */
@Tag("integration")
class NonClassTypeinfoIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource("_ZTIPKc, 16", "_ZTIc, 8")
    fun `a non-class typeinfo is laid as its pseudo struct`(symbol: String, length: Int) {
        val fixture = "crypto_mi_test_gcc345.exe"
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        val ctx = loaded.program.defaultContext()
        ctx.importAndAnalyze()

        val at = loaded.program.symbolTable.getGlobalSymbols(symbol).single().address
        val data = checkNotNull(loaded.program.listing.getDataAt(at)) { "nothing laid at $symbol" }
        data.length mustBe length
        val stubs = ctx.diagnostics.degradationTargets()["global-typed-xref-stub"].orEmpty()
        stubs.must("$symbol not typed as a stub") { symbol !in this }
    }
}
