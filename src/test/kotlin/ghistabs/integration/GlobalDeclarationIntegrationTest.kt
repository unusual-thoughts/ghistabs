package ghistabs.integration

import ghistabs.render.Renderer
import ghistabs.render.Renderer.Mode
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/** File-scope declarations in decomp: what gcc wrote for them, and nothing the source didn't. */
@Tag("integration")
class GlobalDeclarationIntegrationTest : FeatureFixtureTest() {
    private fun decomp(fixture: String, file: String): String {
        load(fixture)
        val out = File("build/test-output/global-declarations/$fixture").apply { deleteRecursively() }
        Renderer(Mode.DECOMPILE, program.defaultContext(), artifacts.hints).use { it.renderAll(out) }
        return out.walk().single { it.name == file }.readText()
    }

    // gcc 2.95 and 12 leave `.bss` uninitialized (a pointer read there is `NaP`), gcc 3.3 and 4.1 zero-fill
    // it (`= 0x00000000`, `= { 0, 0.0, "", }`). The source wrote no initializer on any of them (§97).
    @ParameterizedTest
    @ValueSource(
        strings = ["hello_elf_gcc41", "hello_elf_gcc33", "hello_elf_gcc12", "hello_elf_gcc295", "hello_gcc345.exe"],
    )
    fun `a bss global renders no initializer`(fixture: String) {
        val text = decomp(fixture, "hello.cc")
        for (global in listOf("g_cb", "g_val;", "matrix[2][3]", "Shape::count")) {
            text.lines().single { global in it && "(global)" in it }.mustNot("$global initialized") { " = " in this }
        }
        text.lines().single { "g_ld" in it && "(global)" in it }.must("g_ld lost its initializer") { "= 1.5L;" in this }
    }

    // C's `typedef struct {…} div_t;` is a variant of the anonymous struct: `div_t:t(1,1)=(1,2)=s8…` (§93).
    @Test
    fun `a C typedef of an anonymous struct renders once`() {
        val text = decomp("hello_gcc345.exe", "stdlib.h")
        text.must("div_t's body missing") { "} div_t; /* 8 bytes */" in this }
        text.mustNot("div_t typedef'd to itself") { "typedef struct div_t;" in this }
        text.mustNot("ldiv_t typedef'd to itself") { "typedef struct ldiv_t;" in this }
    }
}
