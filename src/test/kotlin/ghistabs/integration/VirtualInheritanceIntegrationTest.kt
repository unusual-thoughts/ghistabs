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
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * `features/hello.cc`'s diamond, on every compiler that built it:
 *
 * ```
 * struct Base { int id; };
 * struct Left : virtual Base { int l; };
 * struct Right : virtual Base { int r; };
 * struct Diamond : Left, Right, Named { int d; };
 * ```
 *
 * No inheritance line says where a virtual base is: gcc ≥ 3.0 writes a vtable offset (`!1,12-96,`),
 * gcc 2.x writes 0. `Base` belongs after the non-virtual data, once, in the complete object, and a
 * class embedded as a base brings only its non-virtual part: `Left` and `Right` are 8 bytes inside
 * `Diamond`, not the 12 they are on their own.
 */
@Tag("integration")
class VirtualInheritanceIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var loaded: LoadedProgram

    @AfterEach
    fun tearDown() {
        if (::loaded.isInitialized) loaded.close()
    }

    @ParameterizedTest
    @MethodSource("hellos")
    fun `a virtual base is laid once, after the non-virtual data`(fixture: String) {
        assumeTrue(Fixtures.accepts(fixture), "excluded by -Pfixture")
        loaded = loadProgram(File(FEATURES, fixture))
        loaded.program.defaultContext().import()

        val left = struct("Left")
        val diamond = struct("Diamond")
        left.vbaseAt() mustBe 8
        left.length mustBe 12
        diamond.vbaseAt() mustBe 32
        diamond.length mustBe 36
        diamond.undefinedBytes().mustBeEmpty("Diamond bytes no component covers")
    }

    private fun struct(name: String): Structure = loaded.program.dataTypeManager.allDataTypes.asSequence()
        .filterIsInstance<Structure>()
        .filter { it.name == name && "!internal" !in it.categoryPath.path }
        .maxBy { it.numDefinedComponents }

    private fun Structure.vbaseAt() = definedComponents.singleOrNull { it.dataType.name == "Base" }?.offset

    private fun Structure.undefinedBytes() = (0 until length).filter { b ->
        definedComponents.none { b in it.offset until it.offset + it.length }
    }

    companion object {
        private val FEATURES = File("src/test/resources/binaries/features")

        @JvmStatic
        fun hellos() = FEATURES.list().orEmpty().filter { it.startsWith("hello_") }.sorted()
    }
}
