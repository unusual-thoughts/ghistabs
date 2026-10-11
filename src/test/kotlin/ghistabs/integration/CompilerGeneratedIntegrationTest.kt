package ghistabs.integration

import ghistabs.render.Renderer
import ghistabs.render.Renderer.Mode
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * gcc defines members `hello.cc` never wrote: `Shape`'s and `Circle`'s copy constructors (`probe` throws
 * a `Circle` by value), `Circle`'s and `Diamond`'s destructors, `Named`'s constructor. gcc 2.95 and
 * gcc ≥ 4.1 date each at its class's line, so in decomp its body took the class's row and the class went
 * to the appendix. gcc 3.x dates it where it was first needed. Decomp lists them, with typeinfo and
 * vtables, in an appendix of their own (render-backlog §82).
 */
@Tag("integration")
class CompilerGeneratedIntegrationTest : FeatureFixtureTest() {
    /** The render up to the compiler-generated appendix, and the appendix. */
    private fun decomp(fixture: String): Pair<String, String> {
        load(fixture)
        val out = File("build/test-output/compiler-generated/$fixture").apply { deleteRecursively() }
        Renderer(Mode.DECOMPILE, program.defaultContext(), artifacts.hints).use { it.renderAll(out) }
        val (written, generated) = out.walk().single { it.name == "hello.cc" }.readText()
            .split("compiler-generated (not in the source)").also { it.size mustBe 2 }
        return written to generated
    }

    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc12", "hello_elf_gcc41", "hello_elf_gcc295"])
    fun `an implicit member dated at its class's line leaves the row to the class`(fixture: String) {
        val (written, generated) = decomp(fixture)
        for (cls in listOf("class Shape {", "class Circle : public Shape {")) {
            written.lines().filter { it.startsWith(cls) && "line already taken" !in it }.mustNotBe(emptyList<String>())
        }
        written.mustNot("copy constructor rendered as written") { "Shape::Shape(Shape *" in this }
        generated.lines().filter { it.startsWith("Shape::Shape(Shape *") && "(implicit member)" in it }.size mustBe 1
        // `struct Named { virtual ~Named() {} … };` writes its destructor on the class's line.
        written.must("Named's written destructor left the canvas") { "Named::~Named(" in this }
        generated.lines().filter { it.startsWith("Named::~Named(") }.mustBeEmpty("Named's written destructor listed")
    }

    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc33", "hello_gcc345.exe"])
    fun `an implicit member gcc 3 dated inside its first user is listed, parameters and all`(fixture: String) {
        val (written, generated) = decomp(fixture)
        generated.must("Circle's copy constructor not listed") {
            lines().any { "Circle::Circle(Circle *" in it && "// L 87 (implicit member)" in it }
        }
        written.mustNot("its parameter left behind") { "_ctor_arg;" in this }
    }

    @ParameterizedTest
    @ValueSource(
        strings = ["hello_elf_gcc12", "hello_elf_gcc41", "hello_elf_gcc33", "hello_elf_gcc295", "hello_gcc345.exe"],
    )
    fun `a class shares its line with the written member gcc dates there`(fixture: String) {
        val (written, _) = decomp(fixture)
        // `struct Named { virtual ~Named() {} char label[8]; };`: both at L43, the class first.
        written.lines().single { it.startsWith("class Named {") }.let { row ->
            row.mustNot("Named displaced") { "line already taken" in this }
            row.must("Named's destructor not on its row, after it") { "Named::~Named(" in substringAfter("};") }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc33", "hello_elf_gcc295"])
    fun `vtables and typeinfo are generated data`(fixture: String) {
        val (written, generated) = decomp(fixture)
        for (prefix in listOf("_ZTI", "_ZTS", "__ti", "__vt_")) {
            written.lines().filter { " $prefix" in it }.mustBeEmpty("$prefix rendered as written")
        }
        generated.must("no generated data listed") { "(generated data)" in this }
    }
}
