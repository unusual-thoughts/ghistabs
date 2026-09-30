package ghistabs.integration

import ghistabs.render.Renderer
import ghistabs.render.Renderer.Mode
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.File

/**
 * `features/latetypedef.c` uses three `latetypedef.h` typedefs first as a global, a parameter and a
 * local. From gcc 10 (`-feliminate-unused-debug-symbols` on by default) each `Name:t(id)` comes after
 * that use, inside whichever function flushed it, with its header line (`SpinnerData` L13) and no N_SOL
 * naming the header, so the line is right but the file is not (render-backlog §85). gcc 9 opens an
 * `N_BINCL` for the header and keeps them there.
 */
@Tag("integration")
class LateTypedefIntegrationTest : FeatureFixtureTest() {
    private fun skeleton(fixture: String, file: String = "latetypedef.c"): String {
        load(fixture)
        val out = File("build/test-output/latetypedef/$fixture").apply { deleteRecursively() }
        Renderer(Mode.SKELETON, program.defaultContext(), artifacts.hints).use { it.renderAll(out) }
        return out.walk().single { it.name == file }.readText()
    }

    @ParameterizedTest
    @ValueSource(strings = ["latetypedef_elf64_gcc10", "latetypedef_elf64_gcc12"])
    fun `a typedef carrying its header's line goes to the appendix`(fixture: String) {
        val (laidOut, appendix) = skeleton(fixture).split("displaced declarations").also { it.size mustBe 2 }
        for (name in listOf("StateHash", "Vec", "SpinnerData")) {
            laidOut.lines().filter { "typedef struct $name;" in it }.mustBeEmpty("$name laid out at a header line")
            appendix.must("$name not in the appendix") { "typedef struct $name;" in this }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = ["latetypedef_elf64_gcc9"])
    fun `a typedef in its header's N_BINCL stays out of the including file`(fixture: String) {
        val rendered = skeleton(fixture)
        rendered.lines().filter { "typedef" in it }.mustBeEmpty("header typedefs rendered in latetypedef.c")
    }

    /**
     * gcc 8 opens no N_BINCL for `hello.cc`'s headers, so `sys/types.h`'s typedefs sit at CU scope with
     * their own lines: `__u_short` L31 would land in `Circle`'s copy constructor. A file-scope typedef
     * can't be declared inside one of its CU's functions, so it goes to the appendix.
     */
    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc8"])
    fun `a CU-scope header typedef is not laid out inside a function`(fixture: String) {
        val (laidOut, appendix) = skeleton(fixture, "hello.cc").split("displaced declarations").also {
            it.size mustBe 2
        }
        laidOut.lines().filter { "typedef short unsigned int __u_short;" in it }.mustBeEmpty("__u_short laid out")
        appendix.must("__u_short not in the appendix") { "typedef short unsigned int __u_short;" in this }
    }
}
