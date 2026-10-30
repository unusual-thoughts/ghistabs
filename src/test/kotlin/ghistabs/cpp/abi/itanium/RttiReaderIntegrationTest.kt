package ghistabs.cpp.abi.itanium

import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.Itanium
import ghistabs.cpp.abi.TypeinfoKind
import ghistabs.cpp.abi.isTypeinfo
import ghistabs.integration.FeatureFixtureTest
import ghistabs.test.mustBe
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
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

    // Each test: the program is closed after each.
    @BeforeEach
    fun setUp() {
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

    @Test
    fun `the abi reads a class's bases off the typeinfo in its namespace`() {
        assumeTrue { ztis.keys.containsAll(CLASSES) }
        val reader = Rtti.Reader(program)
        for (zti in ztis.filterKeys { it in CLASSES }.values) {
            val ns = program.symbolTable.getSymbols(zti).first { it.name == ClassNaming.TYPEINFO }.parentNamespace
            Itanium.basesOf(program, ns) mustBe reader.basesOf(zti)
        }
        val diamond = program.symbolTable.getSymbols(ztis.getValue("Diamond"))
            .first { it.name == ClassNaming.TYPEINFO }.parentNamespace
        Itanium.basesOf(program, diamond)?.map { it.isVirtual } mustBe listOf(false, false, false)
    }

    companion object {
        val CLASSES = setOf("Base", "Named", "Shape", "Circle", "Left", "Right", "Diamond")

        @JvmStatic
        fun hellos(): List<File> = FEATURES.listFiles().orEmpty()
            .filter { it.name.startsWith("hello_") }
            .sorted()
    }
}
