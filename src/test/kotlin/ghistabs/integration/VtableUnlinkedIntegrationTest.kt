package ghistabs.integration

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
 * A vtable the binary doesn't hold is no failure to find it. `stringbuf` comes in with libstdc++'s
 * headers, but nothing in xmltest links a member of it, so its vtable was never emitted; `tinyxml_aout_gcc295.o`
 * names `TiXmlDocument`'s vtable only as an external another object defines. A stripped binary's
 * `streambuf` is different: its members are linked, so its vtable is there and only its symbol is gone.
 */
@Tag("integration")
class VtableUnlinkedIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource(
        "xmltest_gcc421_fullstabs.exe, stringbuf, false",
        "tinyxml_aout_gcc295.o, TiXmlDocument, false",
        "xmltest_gcc421_fullstabs_stripped.exe, streambuf, true",
    )
    fun `only a vtable the binary holds is a failure to find it`(fixture: String, cls: String, failed: Boolean) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        val ctx = loaded.program.defaultContext()
        ctx.import()

        val failures = ctx.diagnostics.degradationTargets()["vtable-failed"].orEmpty()
        (cls in failures) mustBe failed
    }

    /** The other side of the same lookup: the vtables a gcc 2.x object does define are found by their symbols. */
    @ParameterizedTest
    @CsvSource("tinyxml_aout_gcc295.o")
    fun `a vtable the binary holds is laid`(fixture: String) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        val ctx = loaded.program.defaultContext()
        ctx.import()

        (ctx.diagnostics["vtable-applied"] > 0) mustBe true
    }
}
