package ghicpp.stl

import ghidra.app.util.opinion.PeLoader
import ghidra.program.model.listing.Program
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * The MSVC runtime a program links: the toolset `version` its standard library comes from, and whether it
 * is the debug build, whose iterator-debugging containers are laid out differently.
 *
 * The containers are templates compiled into the program, so a program has their layouts whether it imports
 * `MSVCP<nn>.DLL`, only the C runtime (`VCRUNTIME<nn>.DLL`, `MSVCR<nn>.DLL`), or links the runtime
 * statically, where the PE header's linker version names the toolset.
 */
data class MsvcRuntime(val version: Int, val debug: Boolean) {
    /** The bundled archive of this runtime's standard library for [pointerSize], if there is one. */
    fun archive(pointerSize: Int): String? {
        val arch = when (pointerSize) {
            4 -> "x86"
            8 -> "x64"
            else -> return null
        }
        // VC6's headers lay nothing out differently under _DEBUG: its debug runtime has the release layouts.
        val debugLayouts = debug && version != 60
        return "msvcp$version${if (debugLayouts) "d" else ""}_$arch".takeIf { it in BUNDLED }
    }

    companion object {
        private val STL = Regex("""MSVCP(\d+)(\w*)\.DLL""", RegexOption.IGNORE_CASE)
        private val CRT = Regex("""(?:VCRUNTIME|MSVCR)(\d+)(\w*)\.DLL""", RegexOption.IGNORE_CASE)

        /** The debug C runtime of the toolsets since 2015, beside `VCRUNTIME140D.DLL`. */
        private const val DEBUG_UCRT = "UCRTBASED.DLL"

        /** What [ARCHIVES] ships: the archives CI builds (see tools/stl-archives). */
        val BUNDLED = setOf(
            "msvcp140_x86",
            "msvcp140_x64",
            "msvcp140d_x86",
            "msvcp140d_x64",
            "msvcp90_x86",
            "msvcp90_x64",
            "msvcp60_x86",
        )

        /**
         * The runtime among a program's imported [libraries]: the standard library DLL's, else the C runtime's,
         * which comes from the same toolset. msvcp140 comes with satellites (`MSVCP140_1.DLL`,
         * `MSVCP140_ATOMIC_WAIT.DLL`, debug `MSVCP140_1D.DLL`, `MSVCP140D_ATOMIC_WAIT.DLL`) and vcruntime140
         * with `VCRUNTIME140_1.DLL`, that say the same thing as the main DLL.
         */
        fun of(libraries: Iterable<String>): MsvcRuntime? {
            val names = libraries.toList()
            return names.firstNotNullOfOrNull { match(STL, it) }
                ?: names.firstNotNullOfOrNull { match(CRT, it) }
                    ?.let { if (names.any { it.equals(DEBUG_UCRT, true) }) it.copy(debug = true) else it }
        }

        private fun match(dll: Regex, name: String): MsvcRuntime? {
            val match = dll.matchEntire(name) ?: return null
            val rest = match.groupValues[2].uppercase()
            val debug = rest == "D" || rest.startsWith("D_") || (rest.startsWith("_") && rest.endsWith("D"))
            return MsvcRuntime(match.groupValues[1].toInt(), debug)
        }

        /**
         * The runtime of [program] from its imports, else, for a PE that imports neither runtime, the toolset
         * of the linker that built it: the runtime it linked statically. A static link reads as the release runtime,
         * since nothing left in the program tells `/MTd` from `/MT`.
         */
        fun of(program: Program): MsvcRuntime? = of(program.externalManager.externalLibraryNames.asIterable())
            ?: linkerVersion(program)?.let { (major, minor) -> toolset(major, minor) }
                ?.let { MsvcRuntime(it, debug = false) }

        /**
         * The toolset whose linker writes [major].[minor] into a PE header, as the runtime DLLs number it:
         * 14.x (Visual Studio 2015 to 2022) is 140, 7.10 (2003) 71.
         */
        fun toolset(major: Int, minor: Int): Int? = when (major) {
            14, 12, 11, 10, 9, 8 -> major * 10
            7 -> if (minor >= 10) 71 else 70
            6 -> 60
            else -> null
        }

        /** The linker version in [program]'s PE optional header, which the loader maps at the image base. */
        fun linkerVersion(program: Program): Pair<Int, Int>? {
            if (program.executableFormat != PeLoader.PE_NAME) return null
            val base = program.imageBase
            if (program.memory.getBlock(base)?.isInitialized != true) return null
            val head = ByteArray(HEADERS)
            val read = program.memory.getBytes(base, head)
            val bytes = ByteBuffer.wrap(head, 0, read).order(ByteOrder.LITTLE_ENDIAN)
            if (read < 0x40 || bytes.getShort(0).toInt() != 0x5A4D) return null // MZ
            val pe = bytes.getInt(0x3C)
            if (pe !in 0..read - 28 || bytes.getInt(pe) != 0x4550) return null // PE\0\0
            return (head[pe + 26].toInt() and 0xFF) to (head[pe + 27].toInt() and 0xFF)
        }

        /** How much of a PE's start holds its headers, the optional header's linker version among them. */
        private const val HEADERS = 0x1000

        /**
         * The runtimes' archives, built on Ghidra 10.4 from their PDBs (see tools/stl-archives), in the
         * extension's `data/typeinfo/msvc`.
         */
        val ARCHIVES = StlArchives("msvc", BUNDLED)
    }
}
