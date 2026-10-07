package ghistabs.materialize.cpp.abi

import ghidra.program.model.listing.GhidraClass
import ghistabs.Demangler
import ghistabs.functions
import ghistabs.integration.FeatureFixtureTest
import ghistabs.isMethod
import ghistabs.test.mustBe
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.BeforeParameterizedClassInvocation
import org.junit.jupiter.params.Parameter
import org.junit.jupiter.params.ParameterizedClass
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

@Tag("integration")
@ParameterizedClass
@MethodSource("hellos")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RttiReaderIntegrationTest : FeatureFixtureTest() {
    @field:Parameter(0)
    lateinit var fixture: File

    // Read off each fixture's own program: a lazy would keep the first fixture's addresses.
    val ztis get() =
        program.symbolTable.symbolIterator.iterator().asSequence()
            .filter { it.isTypeinfo }
            .mapNotNull { Itanium.typeinfoClassOf(it.name)?.to(it.address) }
            .toMap()

    @BeforeParameterizedClassInvocation
    fun setUp(fixture: File) {
        assumeTrue(fixture.exists(), "Skipping: ${fixture.path} absent, must be added manually")
        load(fixture.name)
    }

    @Test
    fun `classes get their correct typeinfo kinds`() {
        assumeTrue { ztis.keys.containsAll(CLASSES) }
        val reader = Rtti.Reader(program)
        val kinds = ztis.filter { it.key in CLASSES }.mapValues { reader.kindOf(it.value) }
        kinds mustBe mapOf(
            "Base" to TypeinfoKind.CLASS, // no base
            "Named" to TypeinfoKind.CLASS, // no base, virtual destructor
            "Shape" to TypeinfoKind.CLASS, // no base, virtual methods
            "Circle" to TypeinfoKind.SI, // : public Shape
            "Left" to TypeinfoKind.VMI, // : virtual Base
            "Right" to TypeinfoKind.VMI, // : virtual Base
            "Diamond" to TypeinfoKind.VMI, // : Left, Right, Named
        )
    }

    companion object {
        val CLASSES = setOf("Base", "Named", "Shape", "Circle", "Left", "Right", "Diamond")

        @JvmStatic
        fun hellos(): List<File> = FEATURES.listFiles().orEmpty()
            .filter { it.name.startsWith("hello_") }
            .sorted()
    }
}
