package ghistabs.render

import ghistabs.integration.FeatureFixtureTest
import ghistabs.render.Renderer.Mode
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * Decomp anchors every statement of a one-line body at that line, so all but the first slide down. In
 * `hello.cc` they slid onto `Diamond`'s row and sent the class to the appendix: gcc 2.95 dates it at its
 * `};` L48, under `operator+=` at L47; gcc 3.3, 3.4 and MinGW 3.4.5 at L44, under `~Named` at L43
 * (render-backlog §105).
 */
@Tag("integration")
class SlidingBodyIntegrationTest : FeatureFixtureTest() {
    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc295", "hello_elf_gcc33", "hello_elf_gcc34", "hello_gcc345.exe"])
    fun `a one-line body's statements stop above the next class`(fixture: String) {
        load(fixture)
        val out = File("build/test-output/sliding-body/$fixture").apply { deleteRecursively() }
        Renderer(Mode.DECOMPILE, program.defaultContext(), artifacts.hints).use { it.renderAll(out) }
        val render = out.walk().single { it.name == "hello.cc" }.readText()
        val diamond = render.lines().filter { it.contains(Regex("""^\S.*\bDiamond : """)) }
        diamond.mustNotBeEmpty("Diamond's opener not rendered")
        diamond.filter { "line already taken" in it }.mustBeEmpty("Diamond evicted")
    }
}
