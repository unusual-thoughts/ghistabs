package ghistabs.materialize.cpp

import ghidra.program.model.data.Structure
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer.Companion.import
import ghistabs.integration.Fixtures
import ghistabs.loadProgram
import ghistabs.materialize.cpp.abi.Gcc2
import ghistabs.test.defaultContext
import ghistabs.test.mustBe
import ghistabs.test.mustBeNull
import ghistabs.test.mustBeTrue
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.io.File

/**
 * gcc 2.x gives a secondary vtable its own symbol, `_vt<m><class><m><base>`, instead of packing it
 * behind the primary. libg++'s streams reach `ios` virtually, and a class whose polymorphic bases are
 * all virtual carries only these: `_vt$9TeeStream$3ios` and no `_vt$9TeeStream`, `_vt.8iostream.3ios`
 * and no `_vt.8iostream`. That table is laid anyway, filled from its slots and labelled
 * `internal_vftable` in the class's namespace at the record start its vptr holds.
 */
@Tag("integration")
class Gcc2SecondaryVtableIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram
    private val program get() = loaded.program

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @CsvSource(
        "iostream_test_aout_gcc263.o, TeeStream, _vt\$9TeeStream\$3ios",
        "xmltest_elf_gcc272, iostream, _vt.8iostream.3ios",
    )
    fun `a class with only a virtual polymorphic base gets its secondary laid`(
        fixture: String,
        cls: String,
        symbol: String,
    ) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File("src/test/resources/binaries/$fixture"))
        program.defaultContext().import()
        val st = program.symbolTable

        val at = st.getSymbols(symbol).single().address
        st.getSymbols(at).filter { it.name == ClassNaming.vftableLabel(true) }.map { it.parentNamespace.name }
            .mustBe(listOf(cls), "$symbol should carry an internal_vftable label in $cls")
        program.dataTypeManager.allDataTypes.asSequence().filterIsInstance<Structure>()
            .any { it.name == "${cls}_vftable_internal_0" && it.numComponents > 0 }
            .mustBeTrue("${cls}_vftable_internal_0 should be filled from the record's slots")
    }

    /** The names are [ghistabs.Demangler]'s, so this needs Ghidra's native demangler: not a unit test. */
    @Test
    fun `reads the class and the base off a secondary vtable symbol`() {
        Gcc2.secondaryVtableClasses("_vt.8iostream.3ios") mustBe ("iostream" to "ios")
        Gcc2.secondaryVtableClasses($$"__vt$9TeeStream$3ios") mustBe ("TeeStream" to "ios")
        Gcc2.secondaryVtableClasses("_vt.14CExposedStream.11PRevertable") mustBe ("CExposedStream" to "PRevertable")
        // Where the class ends comes off the mangled form: demangled, both read Outer::Inner::ios.
        Gcc2.secondaryVtableClasses($$"_vt$Q25Outer5Inner$3ios") mustBe ("Outer::Inner" to "ios")
        Gcc2.secondaryVtableClasses($$"_vt$5Outer$Q25Inner3ios") mustBe ("Outer" to "Inner::ios")
        // A template's `t` form, which a length-prefix walk cannot read.
        Gcc2.secondaryVtableClasses("_vt.t5Stack1Zi.3ios") mustBe ("Stack<int>" to "ios")
        Gcc2.secondaryVtableClasses("_vt.Q2t5Stack1Zi4Iter.3ios") mustBe ("Stack<int>::Iter" to "ios")
        // A class's own table names one class, not two; three segments are a path through bases.
        Gcc2.secondaryVtableClasses("_vt.8iostream").mustBeNull()
        Gcc2.secondaryVtableClasses("__vt_9TiXmlNode").mustBeNull()
        Gcc2.secondaryVtableClasses("_vt.7Diamond.4Left.4Base").mustBeNull()
    }
}
