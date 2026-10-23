package ghistabs.integration

import ghidra.program.model.data.Pointer
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
 * A member function that inlines another member gets the inlinee's `this` as a local of a nested block,
 * next to its own `this` parameter. libstdc++'s `istream::get(char*,int,char)` (gcc 3.4.5) holds an
 * inlined `this:(0,176)` at `ebp-0x5c` in the block at +0xd2, and `__class_type_info::__do_upcast`
 * (MinGW gcc 3.2.3) an inlined `this:r(1,51)=k(1,35)`, `__upcast_result const *`, in EDX at +0xd. Each is
 * the inlinee's object, not a copy of the parameter, and keeps its type under a suffixed name.
 */
@Tag("integration")
class InlineeThisIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource(
        "xmltest_gcc345.exe, 0042f120, true",
        "features/hello_gcc323_fullstabs.exe, 004027d0, false",
    )
    fun `an inlined member's this is a local of its own`(fixture: String, entry: String, onStack: Boolean) {
        assumeTrue(Fixtures.accepts(File(fixture).name), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        program.defaultContext().import()

        val func = checkNotNull(program.functionManager.getFunctionAt(program.addressFactory.getAddress(entry)))
        val inlinee = checkNotNull(
            func.localVariables.firstOrNull { Regex("this_\\d+").matches(it.name) && it.isStackVariable == onStack },
        ) { "no inlinee this among ${func.localVariables.map { it.name }}" }
        (inlinee.dataType is Pointer) mustBe true
        inlinee.dataType.isEquivalent(func.parameters.single { it.name == "this" }.dataType) mustBe false
    }
}
