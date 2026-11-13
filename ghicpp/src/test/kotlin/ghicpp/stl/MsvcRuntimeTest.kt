package ghicpp.stl

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
}
