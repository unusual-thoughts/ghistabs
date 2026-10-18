package ghistabs.integration

import ghidra.program.model.data.Structure
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
 * Two virtual overloads take one slot name each from what tells them apart. tinyxml's
 * `ToComment() const` and `ToComment()` differ only in the `const`, and gcc 2.x's stab carries only
 * the mangled argument list, so the physname has to be composed before it says anything; libstdc++'s
 * `num_get::do_get` overloads on `long&` and `unsigned long&`, which a leaf `long` can't tell apart.
 */
@Tag("integration")
class VftableSlotNameIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource(
        "tinyxml_aout_gcc295.o, ToComment_const",
        "crypto_mi_test_gcc345.exe, do_get_istreambuf_iterator_istreambuf_iterator_ios_base__Ios_Iostate_unsigned_long",
    )
    fun `virtual overloads take distinct slot names`(fixture: String, slot: String) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        val ctx = loaded.program.defaultContext()
        ctx.import()

        val fields = loaded.program.dataTypeManager.allDataTypes.asSequence()
            .filterIsInstance<Structure>()
            .flatMap { s -> s.definedComponents.mapNotNull { it.fieldName } }
            .toSet()
        fields.must("a slot named $slot") { slot in this }
        val collisions = ctx.diagnostics.degradationTargets()["vftable-slot-name-collision"].orEmpty()
        collisions.must("no counter-named slot") { isEmpty() }
    }
}
