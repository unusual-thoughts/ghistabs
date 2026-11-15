package ghicpp.stl

import ghicpp.Access
import ghidra.program.model.data.CategoryPath
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test
import java.io.File

class MsvcRuntimeTest {
    @Test
    fun `the runtime is the imported MSVCP DLL, debug when it ends in D`() {
        MsvcRuntime.of(listOf("KERNEL32.DLL", "MSVCP90.DLL", "MSVCR90.DLL")) mustBe MsvcRuntime(90, false)
        MsvcRuntime.of(listOf("msvcp140d.dll")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("MSVCP140_1.DLL")) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(listOf("MSVCP140_ATOMIC_WAIT.DLL")) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(listOf("MSVCP140_1D.DLL")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("MSVCP140D_ATOMIC_WAIT.DLL")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("MSVCP90D.DLL", "MSVCR90D.DLL")) mustBe MsvcRuntime(90, true)
    }

    @Test
    fun `without the standard library DLL, the C runtime's names the toolset`() {
        MsvcRuntime.of(listOf("VCRUNTIME140.DLL", "KERNEL32.DLL")) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(listOf("VCRUNTIME140_1.DLL", "VCRUNTIME140.DLL")) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(listOf("VCRUNTIME140D.DLL", "UCRTBASED.DLL")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("VCRUNTIME140_1D.DLL")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("MSVCR90.DLL")) mustBe MsvcRuntime(90, false)
        MsvcRuntime.of(listOf("msvcr100d.dll")) mustBe MsvcRuntime(100, true)
        MsvcRuntime.of(listOf("MSVCRT.DLL", "KERNEL32.DLL")) mustBe null
        MsvcRuntime.of(listOf("MSVCP140.DLL", "UCRTBASED.DLL")) mustBe MsvcRuntime(140, false)
    }

    @Test
    fun `a static link's toolset is its linker's`() {
        MsvcRuntime.toolset(14, 44) mustBe 140
        MsvcRuntime.toolset(14, 0) mustBe 140
        MsvcRuntime.toolset(12, 0) mustBe 120
        MsvcRuntime.toolset(9, 0) mustBe 90
        MsvcRuntime.toolset(7, 10) mustBe 71
        MsvcRuntime.toolset(7, 0) mustBe 70
        MsvcRuntime.toolset(6, 0) mustBe 60
        MsvcRuntime.toolset(13, 0) mustBe null
        MsvcRuntime.toolset(2, 56) mustBe null // GNU ld
    }

    @Test
    fun `only the bundled runtimes have an archive`() {
        MsvcRuntime(90, false).archive(4) mustBe "msvcp90_x86"
        MsvcRuntime(140, true).archive(8) mustBe "msvcp140d_x64"
        MsvcRuntime(90, true).archive(4) mustBe null
        MsvcRuntime(60, false).archive(4) mustBe "msvcp60_x86"
        MsvcRuntime(60, true).archive(4) mustBe "msvcp60_x86"
        MsvcRuntime(60, false).archive(8) mustBe null

        MsvcRuntime(120, false).archive(8) mustBe "msvcp120_x64"
        MsvcRuntime(120, true).archive(4) mustBe null
        MsvcRuntime(80, false).archive(4) mustBe "msvcp80_x86"
        MsvcRuntime(80, false).archive(8) mustBe null
        MsvcRuntime(100, false).archive(4) mustBe null
        MsvcRuntime(140, false).archive(2) mustBe null
    }

    @Test
    fun `a placeholder stands for the archive type at its path without Demangler`() {
        StlApplier.archivePath(CategoryPath("/Demangler/std")) mustBe CategoryPath("/std")
        StlApplier.archivePath(CategoryPath("/Demangler/std/basic_ios<char,std::char_traits<char>_>")) mustBe
            CategoryPath("/std/basic_ios<char,std::char_traits<char>_>")
        StlApplier.archivePath(CategoryPath("/std")) mustBe CategoryPath("/std")
        StlApplier.archivePath(CategoryPath("/Demangler/Foo")) mustBe null
        StlApplier.archivePath(CategoryPath("/Demangler")) mustBe null
    }

    @Test
    fun `a classes file reads back what was written, bases in order`() {
        val classes = StdClasses(
            listOf(
                StdClass(
                    "/std/basic_iostream<char>",
                    listOf(
                        StdBase("/std/basic_istream<char>", Access.PUBLIC, offset = 0),
                        StdBase("/std/basic_ostream<char>", Access.PUBLIC, offset = 16),
                    ),
                ),
                StdClass("/std/basic_istream<char>", listOf(StdBase("/std/basic_ios<char>", Access.PROTECTED, true))),
                StdClass("/std/_Container_base0"),
            ),
        )
        val file = File.createTempFile("std", StdClasses.SUFFIX).apply { deleteOnExit() }
        classes.write(file)
        StdClasses.read(file.inputStream()) mustBe classes
        StdClass("/std/basic_ios<char>").segments mustBe listOf("std", "basic_ios<char>")
    }
}
