package ghicpp.stl

import ghidra.program.model.listing.Program

/**
 * The MSVC runtime a program links: the version of the `MSVCP<nn>.DLL` it imports, and whether it is
 * the debug build, `MSVCP<nn>D.DLL`, whose iterator-debugging containers are laid out differently.
 */
data class MsvcRuntime(val version: Int, val debug: Boolean) {
    /** The bundled archive of this runtime's standard library for [pointerSize], if there is one. */
    fun archive(pointerSize: Int): String? {
        val arch = when (pointerSize) {
            4 -> "x86"
            8 -> "x64"
            else -> return null
        }
        return "msvcp$version${if (debug) "d" else ""}_$arch".takeIf { it in BUNDLED }
    }

    companion object {
        private val DLL = Regex("""MSVCP(\d+)(\w*)\.DLL""", RegexOption.IGNORE_CASE)

        /** What [ARCHIVES] ships: the archives CI builds (see tools/stl-archives). */
        val BUNDLED = setOf(
            "msvcp140_x86",
            "msvcp140_x64",
            "msvcp140d_x86",
            "msvcp140d_x64",
            "msvcp90_x86",
            "msvcp90_x64",
        )

        /**
         * The runtime among a program's imported [libraries]. msvcp140 comes with satellites
         * (`MSVCP140_1.DLL`, `MSVCP140_ATOMIC_WAIT.DLL`, debug `MSVCP140_1D.DLL`, `MSVCP140D_ATOMIC_WAIT.DLL`)
         * that say the same thing as the main DLL.
         */
        fun of(libraries: Iterable<String>): MsvcRuntime? = libraries.firstNotNullOfOrNull { name ->
            val match = DLL.matchEntire(name) ?: return@firstNotNullOfOrNull null
            val rest = match.groupValues[2].uppercase()
            val debug = rest == "D" || rest.startsWith("D_") || (rest.startsWith("_") && rest.endsWith("D"))
            MsvcRuntime(match.groupValues[1].toInt(), debug)
        }

        fun of(program: Program): MsvcRuntime? = of(program.externalManager.externalLibraryNames.asIterable())

        /**
         * The runtimes' archives, built on Ghidra 10.4 from their PDBs (see tools/stl-archives), in the
         * extension's `data/typeinfo/msvc`.
         */
        val ARCHIVES = StlArchives("msvc", BUNDLED)
    }
}
