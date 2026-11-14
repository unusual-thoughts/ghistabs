package ghicpp.score

import ghidrakt.test.TestBinaries

/**
 * `features/hello.cc`'s classes as each bare build of it recovers them. The stripped Itanium builds are scored
 * against the builds they were stripped from, off their RTTI and as if they had none; the no-RTTI gcc 13 build
 * against its unstripped twin's addresses and the gcc 12 stabs' bases; the MSVC builds, which have no twin,
 * against the gcc 12 stabs by name, and without their RTTI against the vtables their RTTI gives.
 */
class HelloScorecardIntegrationTest : ScorecardFixtureTest() {
    override fun cases(): List<ScorecardCase> {
        val mingw = "hello_gcc421.exe"
        val elf = "hello_elf_gcc12"
        val features = TestBinaries.HELLOS

        fun case(subject: String, recovery: Recovery, twin: String? = null, source: String? = null) =
            ScorecardCase(subject, recovery, twin, source, dir = features)

        fun msvc(subject: String, recovery: Recovery) = when (recovery) {
            Recovery.RTTI -> case(subject, recovery, source = elf)
            Recovery.NO_RTTI -> case(subject, recovery, twin = subject, source = elf).copy(twinRecovered = true)
        }.copy(compiler = "windows")

        return listOf(
            case("hello_gcc421_stripped.exe", Recovery.RTTI, twin = mingw),
            case("hello_gcc421_stripped.exe", Recovery.RTTI, twin = mingw).copy(labelled = true),
            case("hello_gcc421_stripped.exe", Recovery.NO_RTTI, twin = mingw),
            case("hello_gcc421_stripped.exe", Recovery.NO_RTTI, twin = mingw).copy(labelled = true),
            case("hello_elf_gcc12_stripped", Recovery.RTTI, twin = elf),
            case("hello_elf_gcc12_stripped", Recovery.NO_RTTI, twin = elf),
            case(
                "hello_elf64_gcc13_nortti_stripped",
                Recovery.NO_RTTI,
                twin = "hello_elf64_gcc13_nortti",
                source = elf,
            ),
        ) + listOf("hello_msvc.exe", "hello_msvc_clang.exe").flatMap { exe -> Recovery.entries.map { msvc(exe, it) } }
    }
}
