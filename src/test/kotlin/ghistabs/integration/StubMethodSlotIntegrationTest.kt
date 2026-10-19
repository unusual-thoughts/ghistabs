package ghistabs.integration

import ghidra.program.model.data.FunctionDefinition
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.loadProgram
import ghistabs.test.*
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * gcc 2.95 states a method's type as a stub, `##<ret>;`: a return type, and neither `this` nor any
 * parameter. That is its normal form, not a broken emitter, and a vtable slot can take its parameters
 * from the physname the way gdb's `check_stub_method` does: `TiXmlBase::Parse(const char*,
 * TiXmlParsingData*, TiXmlEncoding)`.
 */
@Tag("integration")
class StubMethodSlotIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @Test
    fun `a stub method's vtable slot takes its parameters from the physname`() {
        val fixture = "tinyxml_aout_gcc295.o"
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        val ctx = loaded.program.defaultContext()
        ctx.import()

        val parse = loaded.program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<FunctionDefinition>()
            .filter { it.name == "Parse" && "TiXmlBase" in it.categoryPath.path }
            .toList()
        parse.must("TiXmlBase's Parse slot") { isNotEmpty() }
        parse.forEach { it.arguments.size mustBe 4 }
        val flagged = ctx.diagnostics.degradationTargets()["function-this-synthesized"].orEmpty()
        flagged.must("no stub flagged") { isEmpty() }
    }
}
