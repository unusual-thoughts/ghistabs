package ghicpp.stl

import ghicpp.Access
import ghidra.program.model.data.CategoryPath
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class MsvcRuntimeTest {
    @Test
    fun `the runtime is the imported MSVCP DLL, debug when it ends in D`() {
        MsvcRuntime.of(listOf("KERNEL32.DLL", "MSVCP90.DLL", "MSVCR90.DLL")) mustBe MsvcRuntime(90, false)
        MsvcRuntime.of(listOf("msvcp140d.dll")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("MSVCP140_1.DLL")) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(listOf("MSVCP140_ATOMIC_WAIT.DLL")) mustBe MsvcRuntime(140, false)
        MsvcRuntime.of(listOf("MSVCP140_1D.DLL")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("MSVCP140D_ATOMIC_WAIT.DLL")) mustBe MsvcRuntime(140, true)
        MsvcRuntime.of(listOf("VCRUNTIME140.DLL", "KERNEL32.DLL")) mustBe null
    }

    @Test
    fun `only the bundled runtimes have an archive`() {
        MsvcRuntime(90, false).archive(4) mustBe "msvcp90_x86"
        MsvcRuntime(140, true).archive(8) mustBe "msvcp140d_x64"
        MsvcRuntime(90, true).archive(4) mustBe null
        MsvcRuntime(100, false).archive(4) mustBe null
        MsvcRuntime(140, false).archive(2) mustBe null
    }

    @Test
    fun `a placeholder stands for the archive type at its path without Demangler`() {
        MsvcStlApplier.archivePath(CategoryPath("/Demangler/std")) mustBe CategoryPath("/std")
        MsvcStlApplier.archivePath(CategoryPath("/Demangler/std/basic_ios<char,std::char_traits<char>_>")) mustBe
            CategoryPath("/std/basic_ios<char,std::char_traits<char>_>")
        MsvcStlApplier.archivePath(CategoryPath("/std")) mustBe CategoryPath("/std")
        MsvcStlApplier.archivePath(CategoryPath("/Demangler/Foo")) mustBe null
        MsvcStlApplier.archivePath(CategoryPath("/Demangler")) mustBe null
    }

    @Test
    fun `a classes file gives each class its bases in order`() {
        val text = "C\t/std/basic_iostream<char>\n" +
            "\tB\tpublic\t0\t/std/basic_istream<char>\n" +
            "\tB\tpublic\t16\t/std/basic_ostream<char>\n" +
            "C\t/std/basic_istream<char>\n" +
            "\tV\tprotected\t0\t1\t/std/basic_ios<char>\n" +
            "C\t/std/_Container_base0\n"
        StdClass.parse(text) mustBe listOf(
            StdClass(
                "/std/basic_iostream<char>",
                listOf(
                    StdBase("/std/basic_istream<char>", Access.PUBLIC, isVirtual = false, offset = 0),
                    StdBase("/std/basic_ostream<char>", Access.PUBLIC, isVirtual = false, offset = 16),
                ),
            ),
            StdClass(
                "/std/basic_istream<char>",
                listOf(StdBase("/std/basic_ios<char>", Access.PROTECTED, isVirtual = true, offset = null)),
            ),
            StdClass("/std/_Container_base0", emptyList()),
        )
        StdClass("/std/basic_ios<char>", emptyList()).segments mustBe listOf("std", "basic_ios<char>")
    }
}
