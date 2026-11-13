package ghicpp.stl

import ghidra.program.database.data.DataTypeManagerDB
import ghidra.program.database.data.replaceDataTypesBatched
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import java.io.File

/**
 * The MSVC runtime a program links: the version of the `MSVCP<nn>.DLL` it imports, and whether it is
 * the debug build, `MSVCP<nn>D.DLL`, whose iterator-debugging containers are laid out differently.
 */
data class MsvcRuntime(val version: Int, val debug: Boolean) {
    /** The bundled archive of this runtime's standard library layouts for [pointerSize], if there is one. */
    fun archive(pointerSize: Int): String? {
        val arch = when (pointerSize) {
            4 -> "x86"
            8 -> "x64"
            else -> return null
        }
        return "msvcp$version${if (debug) "d" else ""}_$arch.gdt".takeIf { it in BUNDLED }
    }

    companion object {
        private val DLL = Regex("""MSVCP(\d+)(\w*)\.DLL""", RegexOption.IGNORE_CASE)

        /** What [MsvcStlArchives] ships: the layouts CI builds (see tools/stl-archives). */
        val BUNDLED = setOf(
            "msvcp140_x86.gdt", "msvcp140_x64.gdt",
            "msvcp140d_x86.gdt", "msvcp140d_x64.gdt",
            "msvcp90_x86.gdt", "msvcp90_x64.gdt",
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
    }
}

/** The bundled archives, each copied out of the jar once: a [FileDataTypeManager] opens only a file. */
object MsvcStlArchives {
    private val dir by lazy {
        File(System.getProperty("java.io.tmpdir"), "ghicpp-stl-${System.getProperty("user.name")}").apply { mkdirs() }
    }

    fun open(name: String): FileDataTypeManager {
        require(name in MsvcRuntime.BUNDLED) { "no bundled archive $name" }
        val bytes = checkNotNull(javaClass.getResourceAsStream("/ghicpp/stl/$name")) { "missing resource $name" }
            .use { it.readBytes() }
        val file = File(dir, name)
        if (!file.isFile || !file.readBytes().contentEquals(bytes)) {
            val tmp = File.createTempFile(name, ".tmp", dir)
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(file)) {
                file.delete()
                check(tmp.renameTo(file)) { "cannot write $file" }
            }
        }
        return FileDataTypeManager.openFileArchive(file, false)
    }
}

/**
 * Fills the program's empty `std` structs from an [archive] of the runtime's layouts. Ghidra's Microsoft
 * demangler makes an empty placeholder for each class a demangled method belongs to, at the class's
 * namespace path under `/Demangler`, and the archive files each type at that same path without it. So
 * a placeholder `/Demangler/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>` is
 * replaced, at every use, by the archive's `/std/basic_string<…>`, and an empty one already at
 * `/std/…` is filled in place.
 *
 * Runs in the caller's transaction.
 */
class MsvcStlApplier(private val program: Program, private val archive: DataTypeManager) {
    data class Result(val replaced: Int, val filled: Int)

    fun apply(): Result {
        val dtm = program.dataTypeManager
        val stubs = mutableListOf<Pair<Structure, Composite>>()
        dtm.allStructures.forEach { stub ->
            if (!stub.isNotYetDefined) return@forEach
            val path = archivePath(stub.categoryPath) ?: return@forEach
            val layout = archive.getDataType(DataTypePath(path, stub.name)) as? Composite ?: return@forEach
            if (!layout.isNotYetDefined) stubs.add(stub to layout)
        }
        if (stubs.isEmpty()) return Result(0, 0)

        // An empty struct already at the archive's path is filled in place by the conflict handler; a
        // placeholder under /Demangler is swapped for the resolved type everywhere it is used.
        val resolved = stubs.map { (stub, layout) ->
            stub to dtm.resolve(layout, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER)
        }
        val replacements = resolved.filter { (stub, type) -> stub !== type && dtm.contains(stub) }
            .map { (stub, type) -> stub as DataType to type }
        (dtm as DataTypeManagerDB).replaceDataTypesBatched(replacements)
        return Result(replacements.size, stubs.size - replacements.size)
    }

    companion object {
        private val ROOTS = setOf("std", "stdext")

        /** Where the archive files the type a placeholder at [category] stands for; null outside std. */
        fun archivePath(category: CategoryPath): CategoryPath? {
            val names = category.pathElements.toList()
                .let { if (it.firstOrNull() == "Demangler") it.drop(1) else it }
            if (names.firstOrNull() !in ROOTS) return null
            return CategoryPath(CategoryPath.ROOT, names)
        }
    }
}
