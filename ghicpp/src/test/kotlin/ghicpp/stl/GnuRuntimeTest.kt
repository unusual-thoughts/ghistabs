package ghicpp.stl

import ghidra.app.util.opinion.ElfLoader
import ghidra.app.util.opinion.PeLoader
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class GnuRuntimeTest {
    private fun of(format: String, libraries: List<String>, vararg symbols: String) =
        GnuRuntime.of(format, libraries) { symbols.asSequence() }

    @Test
    fun `an ELF importing libstdc++ uses gcc's, a PE importing it MinGW's`() {
        of(ElfLoader.ELF_NAME, listOf("libm.so.6", "libstdc++.so.6", "libc.so.6")) mustBe GnuRuntime(false)
        of(PeLoader.PE_NAME, listOf("KERNEL32.DLL", "libstdc++-6.dll", "msvcrt.dll")) mustBe GnuRuntime(true)
        of(ElfLoader.ELF_NAME, listOf("libc.so.6")) mustBe null
        of("Mac OS X Mach-O", listOf("libstdc++.so.6")) mustBe null
    }

    @Test
    fun `a static link shows in the library's mangled std functions, but not libc++'s`() {
        of(ElfLoader.ELF_NAME, listOf("libc.so.6"), "_ZNSt8ios_base4InitC1Ev") mustBe GnuRuntime(false)
        of(PeLoader.PE_NAME, listOf("msvcrt.dll"), "__ZNKSt5ctypeIcE8do_widenEc") mustBe GnuRuntime(true)
        of(ElfLoader.ELF_NAME, listOf("libc++.so.1"), "_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backERKi") mustBe null
    }

    @Test
    fun `gcc 3's libstdc++, before 3_4's ABI, shows in its soname or its allocator`() {
        of(ElfLoader.ELF_NAME, listOf("libstdc++.so.5", "libc.so.6")) mustBe GnuRuntime(false, legacy = true)
        of(
            ElfLoader.ELF_NAME,
            listOf("libc.so.6"),
            "_ZNSt8ios_base4InitC1Ev",
            "_ZNSt24__default_alloc_templateILb1ELi0EE8allocateEj",
        ) mustBe GnuRuntime(false, legacy = true)
        of(ElfLoader.ELF_NAME, listOf("libstdc++.so.6"), "_ZNSt24__default_alloc_templateILb1ELi0EE8allocateEj") mustBe
            GnuRuntime(false)
    }

    @Test
    fun `the archive is the architecture's, MinGW's apart`() {
        GnuRuntime(false).archive(8) mustBe "libstdcxx_x64"
        GnuRuntime(false).archive(4) mustBe "libstdcxx_x86"
        GnuRuntime(false).archive(2) mustBe null
        GnuRuntime(true).archive(8) mustBe "libstdcxx_mingw_x64"
        GnuRuntime(true).archive(4) mustBe "libstdcxx_mingw_x86"
        GnuRuntime(false, legacy = true).archive(4) mustBe "libstdcxx5_x86"
        GnuRuntime(false, legacy = true).archive(8) mustBe "libstdcxx5_x64"
        GnuRuntime(true, legacy = true).archive(4) mustBe null
    }
}
