package ghicpp.stl

import ghidra.app.util.opinion.ElfLoader
import ghidra.app.util.opinion.PeLoader
import ghidra.program.model.listing.Program

/**
 * The libstdc++ a program uses: gcc's, or MinGW-w64's in a PE ([mingw]), whose `wchar_t`, `long` and x86
 * alignment differ from the ELF targets'. The containers are templates compiled into the program, so a
 * program has their layouts whether it imports `libstdc++.so.6` or `libstdc++-6.dll`, or links the library
 * statically.
 */
data class GnuRuntime(val mingw: Boolean) {
    /** The bundled archive of this runtime's standard library for [pointerSize], if there is one. */
    fun archive(pointerSize: Int): String? {
        val arch = when (pointerSize) {
            4 -> "x86"
            8 -> "x64"
            else -> return null
        }
        return "libstdcxx${if (mingw) "_mingw" else ""}_$arch".takeIf { it in BUNDLED }
    }

    companion object {
        /** What [ARCHIVES] ships: the archives CI builds (see tools/stl-archives). */
        val BUNDLED = setOf("libstdcxx_x86", "libstdcxx_x64")

        private val SHARED = Regex("""libstdc\+\+(?:\.so(?:\.\d+)*|-\d+\.dll)""", RegexOption.IGNORE_CASE)

        /**
         * The Itanium mangling of a `std::` function, a member's or a free one's, with the leading `_` an x86
         * PE's symbols carry; libc++ files its own under `std::__1` (`_ZNSt3__1`).
         */
        private val STD = Regex("""_?_Z(?:NK?St|St)(?!3__1)\w*""")

        /**
         * The runtime of a program of executable [format] (ELF or PE) from the [libraries] it imports, else,
         * for a static link, from its [symbols]: any libstdc++ function mangled the Itanium way.
         */
        fun of(format: String, libraries: Iterable<String>, symbols: () -> Sequence<String>): GnuRuntime? {
            val mingw = when (format) {
                PeLoader.PE_NAME -> true
                ElfLoader.ELF_NAME -> false
                else -> return null
            }
            val linked = libraries.any { SHARED.matches(it) } || symbols().any { STD.matches(it) }
            return if (linked) GnuRuntime(mingw) else null
        }

        /**
         * The runtime of [program]. A PE built with MSVC never counts, though Ghidra's GNU demangler may have
         * a mangled name to read in it.
         */
        fun of(program: Program): GnuRuntime? {
            if (program.executableFormat == PeLoader.PE_NAME && MsvcRuntime.of(program) != null) return null
            return of(program.executableFormat, program.externalManager.externalLibraryNames.asIterable()) {
                val table = program.symbolTable
                // The demangler keeps the mangled name as a label beside the name it gives.
                listOf("_ZNSt*", "_ZNKSt*", "_ZSt*", "__ZNSt*", "__ZNKSt*", "__ZSt*").asSequence()
                    .flatMap { pattern ->
                        table.getSymbolIterator(pattern, true).let { s ->
                            generateSequence { if (s.hasNext()) s.next() else null }
                        }
                    }
                    .map { it.name }
            }
        }

        /** The libstdc++ archives, built on Ghidra 10.4 (see tools/stl-archives), in `data/typeinfo/libstdcxx`. */
        val ARCHIVES = StlArchives("libstdcxx", BUNDLED)
    }
}
