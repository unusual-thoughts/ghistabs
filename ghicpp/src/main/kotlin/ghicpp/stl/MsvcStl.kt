package ghicpp.stl

import generic.jar.ResourceFile
import ghidra.framework.Application
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

        /** What [MsvcStlArchives] ships: the archives CI builds (see tools/stl-archives). */
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
    }
}

/**
 * The runtimes' archives, built on Ghidra 10.4 so every release ghicpp supports opens them (see
 * tools/stl-archives). They ship in the extension's `data/typeinfo/msvc`, where Ghidra lists them with its
 * own archives, so the types a program takes from one stay linked to it; a build that only has ghicpp's
 * jar (the ghistabs extension's tests, say) uses the copies in the jar.
 */
object MsvcStlArchives {
    fun open(name: String): FileDataTypeManager {
        require(name in MsvcRuntime.BUNDLED) { "no bundled archive $name" }
        val shipped = runCatching { Application.findDataFileInAnyModule("typeinfo/msvc/$name.gdt") }.getOrNull()
        val file = shipped?.takeIf { it.exists() } ?: ResourceFile(copyOut(name))
        return FileDataTypeManager.openFileArchive(file, false)
    }

    private val dir by lazy {
        File(System.getProperty("java.io.tmpdir"), "ghicpp-stl-${System.getProperty("user.name")}").apply { mkdirs() }
    }

    private fun copyOut(name: String): File {
        val bytes = checkNotNull(MsvcStlArchives::class.java.getResourceAsStream("/ghicpp/stl/$name.gdt")) {
            "missing resource $name.gdt"
        }.use { it.readBytes() }
        val file = File(dir, "$name.gdt")
        if (!file.isFile || !file.readBytes().contentEquals(bytes)) {
            val tmp = File.createTempFile(name, ".tmp", dir)
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(file)) {
                file.delete()
                check(tmp.renameTo(file)) { "cannot write $file" }
            }
        }
        return file
    }
}

/**
 * Fills the program's empty `std` structs from the runtime's [archive]. Ghidra's Microsoft demangler
 * makes an empty placeholder for each class a demangled method belongs to, at the class's namespace path
 * under `/Demangler`, and the archive files each type at that same path without it. Only the types
 * standing in for a placeholder are resolved, with what they depend on, and they stay linked to the
 * archive they came from. So a placeholder
 * `/Demangler/std/basic_string<char,std::char_traits<char>,std::allocator<char>_>` is replaced, at every
 * use, by the runtime's `/std/basic_string<…>`, and an empty one already at `/std/…` is filled in place.
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
