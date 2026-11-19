package ghicpp.stl

import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidrakt.LoadedProgram
import ghidrakt.loadProgram
import ghidrakt.test.TestBinaries
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/** The runtime of programs that import no `MSVCP<nn>.DLL`. */
@Tag("integration")
class MsvcRuntimeIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun `a program importing only vcruntime140 uses msvcp140's layouts`() = load("hello_msvc.exe", "windows") {
        MsvcRuntime.of(program) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(program)?.archive(program.defaultPointerSize) mustBe "msvcp140_x86"
    }

    @Test
    fun `the linker version comes off the PE header`() = load("hello_msvc.exe", "windows") {
        MsvcRuntime.linkerVersion(program) mustBe (14 to 44)
    }

    @Test
    fun `lld-link writes the version of the MSVC linker it stands in for`() = load("hello_msvc_clang.exe", "windows") {
        MsvcRuntime.linkerVersion(program) mustBe (14 to 0)
    }

    @Test
    fun `a MinGW program has no MSVC runtime`() = load("hello_gcc421_stripped.exe", "gcc") {
        MsvcRuntime.of(program) mustBe null
    }

    @Test
    fun `an ELF has no linker version`() = load("hello_elf_gcc12", "gcc") {
        MsvcRuntime.linkerVersion(program) mustBe null
    }

    private fun load(fixture: String, compiler: String, check: LoadedProgram.() -> Unit) =
        loadProgram(File(TestBinaries.HELLOS, fixture), compiler).use(check)
}
